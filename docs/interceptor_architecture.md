# Frida VPP/VCL Interceptor — Technical Design & Architecture

## 1. Problem Statement

Go programs compile system calls directly into the binary — they bypass `libc` entirely and issue the `SYSCALL` instruction via the Go runtime (`runtime/internal/syscall.Syscall6`). This means VPP's standard interception mechanism, `LD_PRELOAD` with `libvcl_ldpreload.so`, **does not work** — there are no libc function calls to intercept.

Additionally, Go uses its own **register-based calling convention** (Go ABI) which is incompatible with the C **System V AMD64 ABI**. Arguments and return values reside in different registers, and Go errors are 16-byte interface values rather than simple integers.

The interceptor solves both problems by using [Frida](https://frida.re/) to:

1. Replace each Go syscall wrapper function body with a no-op trampoline
2. Read arguments from Go ABI registers in `onEnter`
3. Call the corresponding LDP (VCL LD_PRELOAD) function using C ABI in `onLeave`
4. Write return values back into Go ABI registers, including constructing proper Go error interfaces

---

## 2. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Go Application                          │
│                                                             │
│   net.Listen("tcp4", ":9876")                               │
│    └─→ syscall.socket(AF_INET, SOCK_STREAM, 0)             │
│    └─→ syscall.bind(fd, addr, len)                          │
│    └─→ syscall.Listen(fd, backlog)                          │
│    └─→ syscall.accept4(fd, addr, addrlen, flags)            │
│                                                             │
│   net.Dial("tcp4", "127.0.0.1:9876")                       │
│    └─→ syscall.socket(...)                                  │
│    └─→ syscall.connect(fd, addr, len)                       │
│                                                             │
│   conn.Read(buf) / conn.Write(buf)                          │
│    └─→ syscall.read(fd, buf, len)                           │
│    └─→ syscall.write(fd, buf, len)                          │
└──────────────┬──────────────────────────────────────────────┘
               │
               │  Each syscall.* is a distinct Go symbol
               │  with Go ABI registers
               │
               ▼
┌─────────────────────────────────────────────────────────────┐
│              Frida Interceptor Layer                         │
│                                                             │
│  For each Go syscall function:                              │
│                                                             │
│   ┌──────────────────────────────────────────────────────┐  │
│   │ 1. Interceptor.replace(goFunc, retTrampoline)        │  │
│   │    → Original function body replaced with `ret`      │  │
│   │                                                      │  │
│   │ 2. Interceptor.attach(goFunc, {onEnter, onLeave})    │  │
│   │    → onEnter: save Go ABI regs to this._             │  │
│   │    → onLeave: call LDP func, set Go return regs     │  │
│   └──────────────────────────────────────────────────────┘  │
│                                                             │
│  Bridges Go ABI → C System V ABI via Frida NativeFunction   │
│  Constructs Go error interfaces from C errno                │
│  Tracks VCL fake file descriptors                           │
│  Handles EAGAIN / EINPROGRESS with epoll or spin-wait       │
└──────────────┬──────────────────────────────────────────────┘
               │
               │  C System V ABI calls
               │  (Frida NativeFunction handles register mapping)
               │
               ▼
┌─────────────────────────────────────────────────────────────┐
│         LDP (libvcl_ldpreload.so)                           │
│                                                             │
│  POSIX-compatible socket API that routes to VPP:            │
│   socket() → bind() → listen() → accept4() → ...           │
│                                                             │
│  Returns fake file descriptors: fd = vlsh + 32              │
│  Manages VCL sessions, message queue processing             │
└──────────────┬──────────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────────┐
│                  VPP (Session Layer)                         │
│                                                             │
│  User-space TCP/IP stack                                    │
│  VCL session handles (vlsh) map to VPP transport sessions   │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Initialization Flow

The script executes in 5 sequential phases at startup:

```
┌─────────────────────────────────────────────────────────────┐
│ Phase 1: Auto-detect Go Binary                              │
│                                                             │
│  Process.enumerateModules()[0]                              │
│    → Scan for Go symbols (syscall.*, runtime.*)             │
│    → Set moduleName                                         │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│ Phase 2: Resolve Go Syscall Symbols                         │
│                                                             │
│  Process.getModuleByName(moduleName).enumerateSymbols()     │
│    → Match against 17 known syscall names                   │
│    → Store address → syscallAddresses map                   │
│                                                             │
│  Symbols resolved:                                          │
│    syscall.socket, syscall.bind, syscall.Listen,            │
│    syscall.accept4, syscall.accept, syscall.connect,        │
│    syscall.setsockopt, syscall.getsockopt,                  │
│    syscall.getsockname, syscall.getpeername,                │
│    syscall.read, syscall.write, syscall.Close,              │
│    syscall.Shutdown, syscall.fcntl,                         │
│    syscall.EpollCtl, syscall.EpollWait                      │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│ Phase 3: Load VCL Library                                   │
│                                                             │
│  if VCL_CONFIG env var not set:                             │
│    → Passthrough mode (no hooks, syscalls go to kernel)     │
│    → Script exits here                                      │
│                                                             │
│  if VCL_CONFIG is set:                                      │
│    → Module.load(libvcl_ldpreload.so)                       │
│    → Frida registers the versioned soname                   │
│      (e.g., libvcl_ldpreload.so.26.06)                      │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│ Phase 4: Resolve LDP Function Pointers & Go Error Symbols   │
│                                                             │
│  findLdpSym() enumerates the LDP module's symbol table      │
│    → Bypasses PLT/GOT (which returns libc's functions)      │
│    → Gets real LDP function addresses in .text              │
│    → Wraps each as Frida NativeFunction                     │
│                                                             │
│  findGoErrnoItab() finds go:itab.syscall.Errno,error        │
│    → Pre-allocates 19 common errno data slots               │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│ Phase 5: Install Per-Syscall Hooks                          │
│                                                             │
│  For each resolved Go syscall symbol:                       │
│    1. Allocate ret trampoline (1-byte 0xC3 in exec memory)  │
│    2. Interceptor.replace(goFunc, trampoline)                │
│    3. Interceptor.attach(goFunc, {onEnter, onLeave})         │
│                                                             │
│  Hook count logged (typically 13 of 17 present in binary)   │
└─────────────────────────────────────────────────────────────┘
```

---

## 4. Go ABI ↔ C System V ABI Bridge

### 4.1 The Core Problem

Go (1.17+, amd64) and C use **completely different registers** for function arguments and return values.

**Go register ABI at `syscall.*` level:**

| Register | Input Role | Output Role |
|----------|-----------|-------------|
| `RAX` | 1st argument | Primary return value (r1) |
| `RBX` | 2nd argument | Secondary return / error itab ptr |
| `RCX` | 3rd argument | Error data ptr / errno |
| `RDI` | 4th argument | — |
| `RSI` | 5th argument | — |
| `R8`  | 6th argument | — |

**C System V AMD64 ABI (used by LDP functions):**

| Register | Input Role | Output Role |
|----------|-----------|-------------|
| `RDI` | 1st argument | — |
| `RSI` | 2nd argument | — |
| `RDX` | 3rd argument | — |
| `RCX` | 4th argument | — |
| `R8`  | 5th argument | — |
| `R9`  | 6th argument | — |
| `RAX` | — | Return value |

Frida's `NativeFunction` automatically handles the C ABI side — when we call `ldp.socket(2, 1, 0)`, Frida places arguments in `RDI`, `RSI`, `RDX` per System V convention. The challenge is reading Go's registers **before** the call and writing Go's registers **after**.

### 4.2 The Trampoline Mechanism

```
 Before hook installation:               After hook installation:

 syscall.socket:                         syscall.socket:
   0x48ff40: PUSH RBP                     0x7f3a00001000: RET  ← trampoline
   0x48ff41: MOV RBP, RSP                   (original body is unreachable)
   0x48ff44: ...
   0x48ff80: SYSCALL
   0x48ff82: ...
   0x48ff90: RET
```

The trampoline is a **single `ret` instruction** (`0xC3`) allocated in executable heap memory:

```javascript
function allocateRetTrampoline() {
    var block = Memory.alloc(Process.pageSize);
    Memory.patchCode(block, 16, function(code) {
        var w = new X86Writer(code, { pc: block });
        w.putRet();
        w.flush();
    });
    return block;
}
```

**Why `ret`?** The trampoline must be a valid function that returns immediately. Frida's `Interceptor.attach` fires `onEnter` before the trampoline executes and `onLeave` after. Since the trampoline does nothing, we have complete control: read Go registers in `onEnter`, call LDP and set return registers in `onLeave`.

### 4.3 Per-Syscall Hook Pattern

Every hook follows the same structure:

```
Go code calls syscall.socket(domain=2, type=1, proto=0)
        │
        │ CPU state: rax=2, rbx=1, rcx=0
        ▼
┌───────────────────────────────────────────────────┐
│  onEnter:                                         │
│    this._domain   = this.context.rax.toInt32()  2 │
│    this._type     = this.context.rbx.toInt32()  1 │
│    this._protocol = this.context.rcx.toInt32()  0 │
│                                                   │
│  (Saved to per-invocation this._ state)           │
└───────────────────┬───────────────────────────────┘
                    │
                    ▼
┌───────────────────────────────────────────────────┐
│  Trampoline: RET                                  │
│  (does nothing — immediate return)                │
└───────────────────┬───────────────────────────────┘
                    │
                    ▼
┌───────────────────────────────────────────────────┐
│  onLeave:                                         │
│                                                   │
│    // Call LDP via C ABI (Frida handles register  │
│    // mapping to RDI, RSI, RDX automatically)     │
│    var ret = ldp.socket(2, 1, 0);                 │
│    // ret = 32 (VCL fake fd = vlsh + 32)          │
│                                                   │
│    // Set Go return registers:                    │
│    retval.replace(32);          // rax = 32 (fd)  │
│    context.rbx = ptr(0);        // rbx = nil itab │
│    context.rcx = ptr(0);        // rcx = nil data │
└───────────────────┬───────────────────────────────┘
                    │
                    ▼
Go receives: fd=32, err=nil ✓
```

### 4.4 Argument Register Mapping Per Syscall

| Syscall | RAX | RBX | RCX | RDI | RSI | R8 |
|---------|-----|-----|-----|-----|-----|-----|
| `socket` | domain | type | protocol | — | — | — |
| `bind` | fd | addr_ptr | addrlen | — | — | — |
| `listen` | fd | backlog | — | — | — | — |
| `accept4` | fd | addr_ptr | addrlen_ptr | flags | — | — |
| `accept` | fd | addr_ptr | addrlen_ptr | — | — | — |
| `connect` | fd | addr_ptr | addrlen | — | — | — |
| `setsockopt` | fd | level | optname | optval_ptr | optlen | — |
| `getsockopt` | fd | level | optname | optval_ptr | optlen_ptr | — |
| `getsockname` | fd | addr_ptr | addrlen_ptr | — | — | — |
| `getpeername` | fd | addr_ptr | addrlen_ptr | — | — | — |
| `read` | fd | buf_ptr | count | — | — | — |
| `write` | fd | buf_ptr | count | — | — | — |
| `close` | fd | — | — | — | — | — |
| `shutdown` | fd | how | — | — | — | — |
| `fcntl` | fd | cmd | arg | — | — | — |
| `EpollCtl` | epfd | op | fd | event_ptr | — | — |
| `EpollWait` | epfd | events_ptr | maxevents | timeout | — | — |

---

## 5. Return Value & Error Handling

### 5.1 Go Return Conventions

Go syscall wrapper functions have two return patterns:

**Pattern A — `(int, error)`:** Used by `socket`, `accept4`, `accept`, `read`, `write`, `fcntl`, `EpollWait`

```
Success: rax = result (fd, byte count, etc.)
         rbx = ptr(0)     ← nil error itab
         rcx = ptr(0)     ← nil error data

Error:   rax = -1
         rbx = itab_ptr   ← go:itab.syscall.Errno,error
         rcx = data_ptr   ← pointer to 8-byte uintptr holding errno
```

**Pattern B — `error`:** Used by `bind`, `listen`, `connect`, `setsockopt`, `getsockopt`, `getsockname`, `getpeername`, `close`, `shutdown`, `EpollCtl`

```
Success: rax = ptr(0)     ← nil error itab (err == nil)
         rbx = ptr(0)     ← nil error data
         rcx = ptr(0)     ← unused (zeroed for safety)

Error:   rax = itab_ptr   ← go:itab.syscall.Errno,error
         rbx = data_ptr   ← pointer to 8-byte uintptr holding errno
         rcx = ptr(0)     ← unused
```

### 5.2 Go Error Interface Construction

```
Go error interface layout (16 bytes):

  ┌────────────────────────────────────────────┐
  │  itab_ptr (8 bytes)                        │
  │  Points to: go:itab.syscall.Errno,error    │
  │  (the interface method table)              │
  ├────────────────────────────────────────────┤
  │  data_ptr (8 bytes)                        │
  │  Points to: heap-allocated uintptr         │
  │  containing the errno value (e.g., 11)     │
  └────────────────────────────────────────────┘
```

**Why `data_ptr` must be a pointer:** Go's `syscall.Errno` type uses a pointer receiver for its `Error()` method. The data word of the interface must be a **pointer to the errno value**, not the value itself. If a raw integer were placed there, Go's runtime would dereference it as a pointer and crash.

**Pre-cached errno slots:** At startup, 19 common errno values (EAGAIN, EINVAL, ECONNREFUSED, etc.) are allocated as persistent 8-byte heap slots. On-demand allocation handles uncommon errnos.

```
Memory layout of pre-cached errno slots:

  _errnoDataCache[11]:  ┌──────────┐
     Frida heap addr ──→│ 0x0B     │  (EAGAIN = 11, stored as uint64)
                        └──────────┘

  _errnoDataCache[111]: ┌──────────┐
     Frida heap addr ──→│ 0x6F     │  (ECONNREFUSED = 111)
                        └──────────┘
```

### 5.3 setGoReturn Flow

```
                    LDP function returns
                           │
                           ▼
                    ┌──────────────┐
                    │ result < 0 ? │
                    └──┬───────┬───┘
                   yes │       │ no
                       ▼       ▼
          ┌────────────────┐  ┌────────────────────────┐
          │ errno =        │  │ returnsInt?             │
          │  getCErrno()   │  │   yes: rax = result     │
          │                │  │         rbx = ptr(0)    │
          │ goErr =        │  │         rcx = ptr(0)    │
          │  goErrFromErrno│  │   no:  rax = ptr(0)     │
          │    (errno)     │  │         rbx = ptr(0)    │
          └───────┬────────┘  │         rcx = ptr(0)    │
                  │           └────────────────────────┘
                  ▼
          ┌────────────────┐
          │ returnsInt?    │
          │  yes:          │
          │   rax = -1     │
          │   rbx = itab   │
          │   rcx = data   │
          │  no:           │
          │   rax = itab   │
          │   rbx = data   │
          │   rcx = ptr(0) │
          └────────────────┘
```

---

## 6. File Descriptor Tracking

### 6.1 VCL Fake File Descriptors

LDP returns **fake file descriptors** that do not exist in the Linux kernel:

```
fd = vlsh + 32

  where vlsh = VCL session handle (0, 1, 2, ...)
  and   32   = LDP_SID_BIT_MIN offset (1 << 5)
```

```
Kernel FDs:  0(stdin)  1(stdout)  2(stderr)  3  4  ...  31
VCL FDs:     32  33  34  35  ...
             │   │   │
             │   │   └── vlsh=2 (e.g., accepted client connection)
             │   └────── vlsh=1 (e.g., accepted client connection)
             └────────── vlsh=0 (e.g., listening socket)
```

These fake FDs **must never reach the kernel**. If Go called the kernel's `read(fd=32, ...)`, it would return `EBADF`. That is why `read`, `write`, `close`, and all other data-path syscalls must also be intercepted.

### 6.2 FD Tracking Map

The interceptor maintains a tracking map `_vclFds` to know:
- Which FDs are VCL-managed (for EAGAIN handling)
- What address family each socket uses (for IPv6 V6ONLY logic)

```
_vclFds = {
    32: { family: 2  },   // AF_INET  — IPv4 listening socket
    33: { family: 2  },   // AF_INET  — accepted connection
    34: { family: 10 },   // AF_INET6 — IPv6 socket
}
```

```
  socket() returns fd=32
       │
       ▼
  trackVclFd(32, AF_INET)  ──→  _vclFds[32] = { family: 2 }
       │
       ▼
  bind(32, ...) → listen(32, ...)
       │
       ▼
  accept4(32, ...) returns fd=33
       │
       ▼
  trackVclFd(33, AF_INET)  ──→  _vclFds[33] = { family: 2 }
       │                               (inherits parent's family)
       ▼
  read(33, ...) → EAGAIN?
       │
       ▼
  isVclFd(33) → true → use epoll-based wait
       │
       ▼
  close(33) → untrackVclFd(33)  ──→  delete _vclFds[33]
```

---

## 7. Blocking & Asynchronous Event Handling

VCL sessions are non-blocking by default. Several syscalls require special handling to bridge VCL's async model with Go's synchronous socket expectations.

### 7.1 Strategy by Syscall

| Syscall | Blocking Strategy | Reason |
|---------|------------------|--------|
| `accept4` / `accept` | **Spin-wait** (1ms loops) | Epoll-based wait consumes too much goroutine stack via NativeFunction calls, causing stack overflow on Go's small 8KB goroutine stacks |
| `connect` | **Epoll-based** (EPOLLOUT, 5s timeout) | Runs on main goroutine with sufficient stack; needs MQ pump for SESSION_CONNECTED |
| `read` | **Epoll-based** (EPOLLIN, 5s timeout) | Runs on connection goroutines with grown stacks; needs MQ pump for data arrival |
| `write` | **Epoll-based** (EPOLLOUT, 5s timeout) | Same as read; also handles ENOTCONN |

### 7.2 Epoll-Based Wait (waitForEvent)

Used by `connect`, `read`, and `write` for EAGAIN/EINPROGRESS handling:

```
waitForEvent(fd, eventMask, timeoutMs):

  ┌──────────────────────────────────────────┐
  │ epfd = ldp.epoll_create1(0)              │
  │                                          │
  │ ev.events = eventMask (EPOLLIN/EPOLLOUT) │
  │ ev.data.fd = fd                          │
  │                                          │
  │ ldp.epoll_ctl(epfd, EPOLL_CTL_ADD,       │
  │               fd, &ev)                   │
  │                                          │
  │ n = ldp.epoll_wait(epfd, &events,        │
  │                    1, timeoutMs)          │
  │     ↓                                    │
  │   This call is critical:                 │
  │   LDP's epoll_wait → vppcom_epoll_wait   │
  │     → vcl_epoll_wait_handle_mq()         │
  │     → Drains VCL worker message queue    │
  │     → Processes pending VPP events       │
  │       (SESSION_CONNECTED, data ready)    │
  │                                          │
  │ ldp.close(epfd)                          │
  │ return n                                 │
  └──────────────────────────────────────────┘
```

**Why epoll_wait is essential:** VCL's `vppcom_session_read()` and `vppcom_session_write()` do **not** process the worker message queue. When VPP completes a TCP handshake, it posts `SESSION_CONNECTED` to the MQ — but without draining the MQ, the session stays in `VCL_STATE_UPDATED` forever. Calling `ldp.epoll_wait()` triggers the MQ drain path.

### 7.3 Spin-Wait (accept4 / accept)

Used only by accept hooks, where epoll-based wait is unsafe:

```
accept4 EAGAIN handling:

  ret = ldp.accept4(fd, addr, addrlen, flags)
       │
       ▼
  ┌─────────────────────────────┐
  │ ret == -1 && errno == EAGAIN│──→ no ──→ return ret
  └─────────────┬───────────────┘
                │ yes
                ▼
  ┌─────────────────────────────┐
  │ Busy-wait 1ms               │
  │ (Date.now() spin loop)      │
  │                             │
  │ Retry ldp.accept4(...)      │
  │                             │
  │ Still EAGAIN? → loop        │
  │ Success?      → return fd   │
  └─────────────────────────────┘
```

### 7.4 Connect EINPROGRESS Handling

```
connect(fd, addr, addrlen):

  ret = ldp.connect(fd, addr, addrlen)
       │
       ▼
  ┌──────────────────────────────────────────┐
  │ ret == -1 && errno == EINPROGRESS/EALREADY│
  └──────────────┬───────────────────────────┘
                 │ yes
                 ▼
  ┌──────────────────────────────────────────┐
  │ waitWritable(fd, 5000)                   │
  │   → epoll_create1 + epoll_ctl(EPOLLOUT)  │
  │   → epoll_wait (5s timeout)              │
  │   → MQ pumped, SESSION_CONNECTED fires   │
  │   → EPOLLOUT ready = session established │
  └──────────────┬───────────────────────────┘
                 │
                 ▼
  Return success to Go:
    rax = 0 (success)
    rbx = ptr(0) (nil itab)
    rcx = ptr(0) (nil data)
```

---

## 8. IPv4 / IPv6 Dual-Stack Handling

### 8.1 The Problem

VPP's LDP creates a companion IPv4 listener when an IPv6 socket binds to `::` (any address). If the Go application also creates an IPv4 socket (e.g., via `net.Listen("tcp", ":9876")` which creates both IPv4 and IPv6 listeners), the second `bind()` fails with `EADDRINUSE`.

### 8.2 The Solution

The interceptor tracks each socket's address family from the `socket()` call. In the `listen()` hook, if the socket is IPv6 (`AF_INET6 = 10`), it injects `IPV6_V6ONLY=1` before calling `ldp.listen()`. This prevents LDP from creating the companion IPv4 listener.

IPv4 sockets are not affected — `IPV6_V6ONLY` is only set on IPv6 sockets.

```
socket(AF_INET6, SOCK_STREAM, 0) → fd=34
  │
  ▼
trackVclFd(34, family=10)   ← AF_INET6 recorded
  │
  ▼
bind(34, [::]:9876, 28)
  │
  ▼
listen(34, 128):
  │
  ├─→ getVclFdFamily(34) == 10 (AF_INET6)?  YES
  │     └─→ setsockopt(34, IPPROTO_IPV6, IPV6_V6ONLY, 1)
  │
  └─→ ldp.listen(34, 128)   ← No companion IPv4 listener created

socket(AF_INET, SOCK_STREAM, 0) → fd=35
  │
  ▼
trackVclFd(35, family=2)    ← AF_INET recorded
  │
  ▼
listen(35, 128):
  │
  ├─→ getVclFdFamily(35) == 10?  NO  ← skip V6ONLY
  │
  └─→ ldp.listen(35, 128)   ← Normal IPv4 listen succeeds
```

---

## 9. MPTCP Compatibility

Go 1.21+ probes for MPTCP (Multipath TCP) support by first attempting `socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP=262)`. VPP does not support MPTCP, and if allowed to proceed, the MPTCP socket competes with the regular TCP socket causing `EADDRINUSE`.

The `socket()` hook detects `protocol == 262` and immediately returns `EPROTONOSUPPORT` (errno 93). This causes Go's net package to fall back to standard TCP without error.

```
Go net.Listen("tcp4", ":9876"):
  │
  ├─→ socket(AF_INET, SOCK_STREAM, 262)  ← MPTCP probe
  │     │
  │     ▼
  │   interceptor returns: fd=-1, err=EPROTONOSUPPORT
  │     │
  │     ▼
  │   Go: "MPTCP not supported, falling back to TCP"
  │
  └─→ socket(AF_INET, SOCK_STREAM, 0)    ← Normal TCP
        │
        ▼
      interceptor: ldp.socket(2, 1, 0) → fd=32 ✓
```

---

## 10. LDP Symbol Resolution

### 10.1 Why Not Use findExport()

Standard `findExportByName()` resolves symbols through the dynamic linker's GOT/PLT. When LDP is loaded, its `socket`, `bind`, etc. symbols interpose libc's versions. But `findExportByName('socket')` may still return **libc's** `socket` from the GOT instead of LDP's actual implementation.

### 10.2 findLdpSym() — Direct Symbol Table Enumeration

```
findLdpSym('socket'):

  1. Find LDP module:
     Process.enumerateModules().some(m =>
       m.name.indexOf('ldpreload') !== -1)

     Note: Module.load() loads the symlink target, but Frida
     registers the versioned soname:
       libvcl_ldpreload.so.26.06  (not libvcl_ldpreload.so)
     So we search by substring match.

  2. Enumerate LDP's own symbol table:
     mod.enumerateSymbols().some(sym =>
       sym.name === 'socket')

     This returns the address in LDP's .text section —
     the actual implementation, not a PLT stub.

  3. Cache the result in _ldpSymCache for reuse.
```

---

## 11. Thread Safety Model

### 11.1 Per-Invocation State

Frida's `Interceptor.attach` provides a **per-invocation `this`** context. Each concurrent call to a hooked function gets its own `this` object. This is critical for Go goroutine safety:

```
Goroutine A (accept loop):          Goroutine B (handling conn):
  │                                   │
  ▼                                   ▼
  onEnter:                            onEnter:
    this._fd = 32  ← separate this    this._fd = 33  ← separate this
    this._addr = 0x7f...              this._buf = 0x7f...
  │                                   │
  ▼                                   ▼
  onLeave:                            onLeave:
    ldp.accept4(32, ...)              ldp.read(33, ...)
    ↑ reads this._fd = 32             ↑ reads this._fd = 33
    (no interference)                 (no interference)
```

### 11.2 Global State Safety

| Global | Access Pattern | Safety |
|--------|---------------|--------|
| `_vclFds` | Write in `socket`/`accept` onLeave, read in `read`/`write`/`listen` onLeave | Safe: Frida JS is single-threaded; Go goroutines are serialized through Frida's JS event loop |
| `_errnoDataCache` | Write-once per errno value, then read-only | Safe: immutable after first write |
| `_ldpSymCache` | Write-once at init, then read-only | Safe: populated during startup |
| `ldp.*` | Read-only `NativeFunction` wrappers | Safe: immutable after init |

---

## 12. Supported Syscalls Reference

| # | Go Symbol | Signature | Return Pattern | LDP Function |
|---|-----------|-----------|---------------|-------------|
| 1 | `syscall.socket` | `(domain, type, proto)` | `(int, error)` | `socket()` |
| 2 | `syscall.bind` | `(fd, addr, addrlen)` | `error` | `bind()` |
| 3 | `syscall.Listen` | `(fd, backlog)` | `error` | `listen()` |
| 4 | `syscall.accept4` | `(fd, addr, addrlen_ptr, flags)` | `(int, error)` | `accept4()` |
| 5 | `syscall.accept` | `(fd, addr, addrlen_ptr)` | `(int, error)` | `accept()` |
| 6 | `syscall.connect` | `(fd, addr, addrlen)` | `error` | `connect()` |
| 7 | `syscall.setsockopt` | `(fd, level, optname, optval, optlen)` | `error` | `setsockopt()` |
| 8 | `syscall.getsockopt` | `(fd, level, optname, optval, optlen_ptr)` | `error` | `getsockopt()` |
| 9 | `syscall.getsockname` | `(fd, addr, addrlen_ptr)` | `error` | `getsockname()` |
| 10 | `syscall.getpeername` | `(fd, addr, addrlen_ptr)` | `error` | `getpeername()` |
| 11 | `syscall.read` | `(fd, buf, count)` | `(int, error)` | `read()` |
| 12 | `syscall.write` | `(fd, buf, count)` | `(int, error)` | `write()` |
| 13 | `syscall.Close` | `(fd)` | `error` | `close()` |
| 14 | `syscall.Shutdown` | `(fd, how)` | `error` | `shutdown()` |
| 15 | `syscall.fcntl` | `(fd, cmd, arg)` | `(int, error)` | `fcntl()` |
| 16 | `syscall.EpollCtl` | `(epfd, op, fd, event_ptr)` | `error` | `epoll_ctl()` |
| 17 | `syscall.EpollWait` | `(epfd, events_ptr, maxevents, timeout)` | `(int, error)` | `epoll_wait()` |

---

## 13. End-to-End Request Flow

### 13.1 Server: Listen and Accept

```
Application: net.Listen("tcp4", ":9876")
    │
    ├──→ syscall.socket(AF_INET=2, SOCK_STREAM=1, MPTCP=262)
    │     hook: return EPROTONOSUPPORT (Go falls back to TCP)
    │
    ├──→ syscall.socket(AF_INET=2, SOCK_STREAM=1, 0)
    │     hook: ldp.socket(2,1,0) → fd=32
    │           trackVclFd(32, AF_INET)
    │           → Go receives fd=32, err=nil
    │
    ├──→ syscall.setsockopt(32, SOL_SOCKET, SO_REUSEADDR, &1, 4)
    │     hook: ldp.setsockopt(32, 1, 2, &1, 4) → 0
    │           → Go receives err=nil
    │
    ├──→ syscall.bind(32, {AF_INET, 0.0.0.0:9876}, 16)
    │     hook: ldp.bind(32, sockaddr, 16) → 0
    │           → Go receives err=nil
    │
    ├──→ syscall.Listen(32, 128)
    │     hook: getVclFdFamily(32)=2 (AF_INET, skip V6ONLY)
    │           ldp.listen(32, 128) → 0
    │           → Go receives err=nil
    │
    ├──→ syscall.getsockname(32, &addr, &len)
    │     hook: ldp.getsockname(32, ...) → 0
    │           → Go receives local address
    │
    └──→ [blocking] syscall.accept4(32, &addr, &len, CLOEXEC)
          hook: ldp.accept4(32, ...) → EAGAIN
                spin-wait 1ms, retry...
                ldp.accept4(32, ...) → fd=33  (client connected!)
                trackVclFd(33, AF_INET)
                → Go receives fd=33, err=nil
```

### 13.2 Client: Connect and Exchange Data

```
Application: net.Dial("tcp4", "127.0.0.1:9876")
    │
    ├──→ syscall.socket(AF_INET=2, SOCK_STREAM=1, 0)
    │     hook: ldp.socket(2,1,0) → fd=32
    │           → Go receives fd=32
    │
    └──→ syscall.connect(32, {127.0.0.1:9876}, 16)
          hook: ldp.connect(32, addr, 16) → -1, errno=EINPROGRESS
                → waitWritable(32, 5000)
                  epoll_create1 → epoll_ctl(EPOLLOUT) → epoll_wait
                  MQ drained → SESSION_CONNECTED processed
                  EPOLLOUT ready
                → Go receives err=nil (success)

Application: conn.Write([]byte("hello"))
    │
    └──→ syscall.write(32, "hello", 5)
          hook: ldp.write(32, buf, 5) → 5
                → Go receives n=5, err=nil

Application: conn.Read(buf)
    │
    └──→ syscall.read(32, buf, 4096)
          hook: ldp.read(32, buf, 4096) → EAGAIN
                isVclFd(32) → true
                waitReadable(32, 5000)
                  epoll_wait → MQ pump → data ready
                ldp.read(32, buf, 4096) → 5 ("hello")
                → Go receives n=5, err=nil
```

### 13.3 Server: Echo Response

```
Server goroutine handling fd=33:

Application: conn.Read(buf)
    │
    └──→ syscall.read(33, buf, 4096)
          hook: ldp.read(33, buf, 4096) → 5 ("hello")
                → Go receives n=5

Application: conn.Write(buf[:5])
    │
    └──→ syscall.write(33, "hello", 5)
          hook: ldp.write(33, buf, 5) → 5
                → Go receives n=5

Application: conn.Close()
    │
    └──→ syscall.Close(33)
          hook: ldp.close(33) → 0
                untrackVclFd(33)
                → Go receives err=nil
```

---

## 14. Configuration & Usage

### 14.1 Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `VCL_CONFIG` | Yes (for VPP mode) | Path to VCL configuration file. If unset, script runs in passthrough mode. |
| `LD_LIBRARY_PATH` | Yes | Must include the directory containing `libvcl_ldpreload.so` and its dependencies. |
| `VCL_LIB_PATH` | No | Override the default path to `libvcl_ldpreload.so`. |

### 14.2 Log Levels

Set `LOG_LEVEL` in the script (default: `2`):

| Level | Output |
|-------|--------|
| `0` | Errors only (hook failures, connect timeouts) |
| `1` | Lifecycle events (symbols found, hooks installed, library loaded) |
| `2` | All syscall invocations with arguments and results |

### 14.3 Running

```bash
# Server — auto-detects binary name, works for any Go executable
VCL_CONFIG=/tmp/vcl.conf frida -f ./my_server -l interceptor.js -- :9876

# Client
VCL_CONFIG=/tmp/vcl.conf frida -f ./my_client -l interceptor.js -- 127.0.0.1:9876

# Attach to a running Go process
VCL_CONFIG=/tmp/vcl.conf frida -p <PID> -l interceptor.js

# Passthrough mode (log syscalls without VPP redirection)
frida -f ./my_server -l interceptor.js
```

### 14.4 Requirements

- **Linux x86_64** (Go ABI and register layout are architecture-specific)
- **Frida 17+** (uses instance methods for `findExportByName`, `X86Writer`)
- **Go binary with symbols** (not stripped with `-ldflags="-s -w"`)
- **VPP build** with `libvcl_ldpreload.so` and session layer enabled

---

## 15. Performance Impact Analysis

### 15.1 Per-Syscall Overhead Breakdown

Every intercepted syscall incurs overhead from Frida's instrumentation framework and the ABI bridge. The table below estimates costs for each component:

```
┌──────────────────────────────────────────────────────────────────────────┐
│                    Per-Syscall Overhead                                   │
├───────────────────────────┬──────────┬───────────────────────────────────┤
│ Component                 │ Cost     │ Notes                             │
├───────────────────────────┼──────────┼───────────────────────────────────┤
│ Frida context switch      │ ~5-10µs  │ JS ↔ native transition, per      │
│ (onEnter + onLeave)       │          │ hook invocation                   │
├───────────────────────────┼──────────┼───────────────────────────────────┤
│ Argument read (onEnter)   │ ~1µs     │ 3-5 register reads via           │
│                           │          │ this.context.rXX                  │
├───────────────────────────┼──────────┼───────────────────────────────────┤
│ NativeFunction call       │ ~1-2µs   │ Frida JS → C ABI trampoline      │
│ (LDP invocation)          │          │ for each ldp.* call              │
├───────────────────────────┼──────────┼───────────────────────────────────┤
│ LDP → VCL → VPP path      │ ~2-5µs   │ LDP routing + VCL session        │
│                           │          │ lookup + shared memory IPC        │
├───────────────────────────┼──────────┼───────────────────────────────────┤
│ Return value encoding     │ ~2µs     │ 3 register writes + optional     │
│                           │          │ itab/data lookup for errors       │
├───────────────────────────┼──────────┼───────────────────────────────────┤
│ TOTAL (per networking     │ ~10-20µs │ Compared to ~1-5µs for a raw     │
│ syscall)                  │          │ kernel syscall                    │
├───────────────────────────┼──────────┼───────────────────────────────────┤
│ Non-networking syscalls    │ 0µs      │ NOT intercepted — zero overhead  │
│ (futex, mmap, nanosleep)  │          │ (per-function hook strategy)     │
└───────────────────────────┴──────────┴───────────────────────────────────┘
```

### 15.2 Blocking Operation Costs

Blocking syscalls incur additional overhead depending on the strategy used:

| Operation | Strategy | Additional Latency | CPU Impact |
|-----------|----------|-------------------|------------|
| `accept4` / `accept` EAGAIN | Spin-wait (1ms loops) | 1ms per retry iteration | **High** — 100% CPU during spin |
| `connect` EINPROGRESS | Epoll-based wait (5s max) | Near-zero when MQ responsive | Low — blocked in epoll_wait |
| `read` EAGAIN (VCL fd) | Epoll-based wait (5s max) | Near-zero when data available | Low — blocked in epoll_wait |
| `write` EAGAIN/ENOTCONN | Epoll-based wait (5s max) | Near-zero when writable | Low — blocked in epoll_wait |

**Why accept uses spin-wait instead of epoll:** Epoll-based waiting calls `NativeFunction` (Frida → C), which uses significant stack space. Go's accept loop typically runs on a goroutine with a small (8KB) stack. The `NativeFunction` call chain can overflow this stack, causing `SIGSEGV`. Spin-wait avoids `NativeFunction` calls during the wait loop — `Date.now()` is a pure JS operation.

### 15.3 Throughput Characteristics

**Strengths:**
- **Zero overhead on non-networking syscalls.** Unlike a `Syscall6`-level hook that intercepts *every* syscall (futex, mmap, clock_gettime, etc.), the per-function hook strategy means only the 17 networking-related Go functions are instrumented. File I/O, memory management, synchronization, and other syscalls pass through unmodified.
- **Full goroutine support.** Multiple connections can be handled concurrently via Go's native goroutines. LDP manages per-thread VCL worker registration transparently.
- **Epoll-based MQ processing.** For `read`/`write`/`connect`, the epoll wait path drains VCL's message queue efficiently rather than busy-polling.

**Limitations:**
- **LDP abstraction overhead.** Each VPP call passes through LDP → VCL → VPP (two layers) instead of calling VLS directly. This adds ~1-2µs per call compared to direct VLS invocation.
- **Accept spin-wait burns CPU.** During periods with no incoming connections, the accept loop spins at 100% CPU in 1ms intervals. For production workloads with infrequent connections, this is suboptimal.
- **Frida JS engine single-threaded.** All hook callbacks execute on Frida's single JS thread. Under high concurrency (many goroutines hitting intercepted syscalls simultaneously), this serialization point can become a bottleneck.

### 15.4 Estimated Performance Profile

```
┌────────────────────────────────────────────────────────────────────┐
│                    Workload Impact Estimate                         │
├─────────────────────────┬──────────────────────────────────────────┤
│ Echo server (few conns) │ ~5-10% throughput reduction vs. kernel   │
│                         │ networking. Dominated by Frida context   │
│                         │ switch overhead per read/write pair.     │
├─────────────────────────┼──────────────────────────────────────────┤
│ HTTP server (short req) │ ~10-15% overhead. Each HTTP exchange     │
│                         │ involves socket+connect or accept, plus  │
│                         │ read+write+close = 4-6 hooked syscalls.  │
├─────────────────────────┼──────────────────────────────────────────┤
│ High-concurrency server │ Limited by Frida JS thread serialization │
│ (100+ goroutines)       │ on hook callbacks. Goroutines themselves │
│                         │ are fine; the hook overhead per-call     │
│                         │ remains constant.                        │
├─────────────────────────┼──────────────────────────────────────────┤
│ Compute-heavy Go app    │ Negligible impact. Non-networking        │
│ (rare socket calls)     │ syscalls have zero interception cost.    │
└─────────────────────────┴──────────────────────────────────────────┘
```

### 15.5 Comparison with Syscall6 Hook Strategy

For context, here is how this per-function approach compares with a single `Syscall6` hook (as used by go-frida-vpp):

| Factor | Per-Function Hooks (this impl) | Single Syscall6 Hook |
|--------|-------------------------------|---------------------|
| Non-network syscall overhead | **Zero** | ~3-5µs each (intercepted, checked, passed through) |
| VPP call path | LDP → VCL → VPP (extra layer) | VLS → VPP (direct) |
| Goroutine support | **Yes** (concurrent connections) | No (clib_mem_init conflict) |
| Hook dispatch | Direct (dedicated per-function) | Switch/dispatch on syscall number |
| Error encoding cost | ~2µs (itab + data lookup) | ~0.5µs (raw errno int) |
