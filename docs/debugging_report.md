# Sessions 2 & 3 Debugging Report — VCL Interception Fixes

**Date:** April 25, 2026  
**Goal:** Complete end-to-end echo test over VPP VCL from two Go binaries (`echo_server`, `echo_client`) via Frida-based syscall interception.

**Status:** ✅ **E2E echo test fully working** as of Session 3.

---

## 1. Starting State

At the beginning of this session, `interceptor_server.js` could bring the server to "Listening" status. The following bugs remained:

| # | Bug | Symptom |
|---|-----|---------|
| 1 | `accept4` returned EBADF to Go | `[server] Accept error: accept4: bad file descriptor` |
| 2 | `connect` returned EINPROGRESS stuck in SO_ERROR polling loop | Client stuck forever |
| 3 | No `read`/`write`/`close` hooks in `interceptor_client.js` | Data transfer would fail after connect |

---

## 2. Bug Deep-Dives and Fixes

### 2.1 LDP Fake FD Numbers (Root Cause of EBADF)

**Discovery:** `ldp.accept4()` returns fake fd numbers. LDP maps VCL session handles to fd numbers using a bit offset:

```c
/* ldp.c */
#define LDP_SID_BIT_MIN  5   /* vlsh_bit_val = (1 << 5) = 32 */
static u32 ldp_vlsh_to_fd(vls_handle_t vlsh) {
    return (vlsh + ldp->vlsh_bit_val);   // fd = vlsh + 32
}
static vls_handle_t ldp_fd_to_vlsh(int fd) {
    if (fd < ldp->vlsh_bit_val) return VLS_INVALID_HANDLE;  // kernel fd
    return (fd - ldp->vlsh_bit_val);   // extract vlsh
}
```

So `socket()` returns fd=32, `accept4()` returns fd=33, etc.  These are **not kernel fds** — the Linux kernel knows nothing about fd=32 in that process.

**Problem flow (before fix):**

```
accept4 hook → ldp.accept4() → returns fd=33 (VCL fake fd)
Go receives fd=33 from accept4 hook
Go calls syscall.read(fd=33, ...) → kernel EBADF (fd 33 doesn't exist in kernel)
Go calls epoll_ctl(epfd, ADD, 33) → kernel EBADF
```

**Fix:** Hook `syscall.read`, `syscall.write`, and `syscall.Close` to route through `ldp.read/write/close`. LDP internally dispatches:
- fd ≥ 32 → VCL path (fake fd)
- fd < 32 → kernel libc path (real fd)

This means the hooks also transparently handle all fd types.

**Code added:**

```javascript
// In ldp object:
read:  new NativeFunction(findLdpSym('read'),  'int', ['int', 'pointer', 'int']),
write: new NativeFunction(findLdpSym('write'), 'int', ['int', 'pointer', 'int']),
close: new NativeFunction(findLdpSym('close'), 'int', ['int']),

// Hook syscall.read (Go ABI: rax=fd, rbx=p.ptr, rcx=p.len → returns int,error)
onEnter: function(args) {
    this._fd  = this.context.rax.toInt32();
    this._buf = this.context.rbx;
    this._len = this.context.rcx.toInt32();
},
onLeave: function(retval) {
    var ret;
    do {
        ret = ldp.read(this._fd, ptr(this._buf.toString()), this._len);
        if (ret === -1 && getCErrno() === 11) {  // EAGAIN
            var deadline = Date.now() + 1;
            while (Date.now() < deadline) {}  // 1ms busy-wait
        }
    } while (ret === -1 && getCErrno() === 11);
    setGoReturn(this.context, retval, ret, 'read', true);
}
```

---

### 2.2 accept4 EBADF → Go Enters Epoll Path

**Problem:** Before the read/write/close fix, even if accept4 returned fd=33 successfully, Go's net package tried to call `epoll_ctl(ADD, fd=33)` on the fake fd → EBADF → Go reported "bad file descriptor" from accept.

**Root cause investigation:**

```
Go's net.(*FD).Accept() flow:
1. Calls syscall.accept4(listenFd, ...) → gets connFd=33 (VCL fake)
2. Calls internal/poll.(*FD).Init(connFd=33)
3. Init calls runtime_pollOpen(fd=33)
4. runtime_pollOpen calls epoll_ctl(ADD, fd=33, EPOLLIN|EPOLLOUT)
5. Kernel: fd=33 is not open → EBADF
6. Go reports "accept4: bad file descriptor"
```

**Fix for accept4 EBADF:** Make accept4 blocking (spin-wait on EAGAIN). When accept4 never returns EAGAIN (because we block until a real connection arrives), Go never enters the "register with epoll" path for non-blocking operation. The Go scheduler sees accept4 returned a valid fd immediately — no epoll needed.

```javascript
onLeave: function(retval) {
    var ret;
    do {
        ret = ldp.accept4(this._fd, ptr(this._addr.toString()),
                          ptr(this._addrlenPtr.toString()), this._flags);
        if (ret === -1 && getCErrno() === 11 /*EAGAIN*/) {
            var deadline = Date.now() + 1;
            while (Date.now() < deadline) {}
        }
    } while (ret === -1 && getCErrno() === 11);
    setGoReturn(this.context, retval, ret, 'accept4', true);
}
```

**Why this works:** Go's `internal/poll` package only registers an fd with epoll when `accept4` returns `EAGAIN` (indicating the fd is in non-blocking mode). If `accept4` returns a valid fd immediately, Go treats it as a blocking accept and doesn't touch epoll.

---

### 2.3 MPTCP (proto=262) Duplicate Listener

**Problem:** Go 1.21+ enables MPTCP by default when creating TCP listeners. It calls `socket(AF_INET6, SOCK_STREAM, IPPROTO_MPTCP=262)` **in addition to** the regular `socket(AF_INET6, SOCK_STREAM, 0)`. Both go through LDP, creating two VCL sessions that both try to `listen()` on port 9876.

**Symptoms observed:**
```
[>] socket(10, 526337, 262)    ← MPTCP socket
[+] socket succeeded: ret=32   ← VCL session 0
[>] socket(10, 526337, 0)      ← regular TCP socket
[+] socket succeeded: ret=33   ← VCL session 1
... (bind/listen for session 0) ...
... (bind/listen for session 1) → EADDRINUSE
```

**Discovery method:** Added `console.log` to socket `onLeave` showing protocol. Saw `protocol=262` for MPTCP socket.

**Root cause:** VPP doesn't support MPTCP (proto=262). When Go's socket(262) call reaches LDP, LDP routes it to VCL which creates a TCP session anyway (ignoring the protocol). Both sessions then compete for the same port.

**Fix:** In socket `onLeave`, reject proto=262 with `EPROTONOSUPPORT` (errno=93). Go falls back to standard TCP.

```javascript
onLeave: function(retval) {
    if (this._protocol === 262) {
        retval.replace(-1);
        this.context.rbx = goErrFromErrno(93).itab;
        this.context.rcx = goErrFromErrno(93).data;
        console.log('[>] socket proto=MPTCP: returning EPROTONOSUPPORT');
        return;
    }
    var ret = ldp.socket(this._domain, this._type, this._protocol);
    setGoReturn(this.context, retval, ret, 'socket', true);
}
```

---

### 2.4 IPv6 Dual-Stack and EADDRINUSE in listen()

**Problem:** Go binds to `[::]:9876` (IPv6 dual-stack). With dual-stack enabled, VPP tries to create BOTH an IPv6 and IPv4 listener on the same port, causing the second `listen()` to fail with EADDRINUSE.

**Logs showing the issue:**
```
[>] listen(32, 4096)
ldp: vppcom_session_listen: ...
[!] listen failed: ret=-1, errno=98  ← EADDRINUSE
```

**Fix:** Set `IPV6_V6ONLY=1` before calling `ldp.listen()`. This makes the socket IPv6-only, disabling dual-stack. VPP then creates only one listener.

```javascript
onLeave: function(retval) {
    var v6onlyBuf = Memory.alloc(4);
    v6onlyBuf.writeInt(1);
    ldp.setsockopt(this._fd, 41 /*IPPROTO_IPV6*/, 26 /*IPV6_V6ONLY*/, v6onlyBuf, 4);
    var ret = ldp.listen(this._fd, this._backlog);
    setGoReturn(this.context, retval, ret, 'listen', false);
}
```

---

### 2.5 Go Error Interface Construction (goErrFromErrno)

**Background:** Go's syscall functions return `(int, error)` or just `error`. The `error` is a Go interface — a 16-byte pair of `(itab_pointer, data_pointer)`. You cannot fake this from JavaScript; you must use real Go runtime objects.

**Previous approach (broken):** Used `syscall.errEAGAIN`, `syscall.errEINVAL`, `syscall.errENOENT` — pre-cached error objects for only three errno values.

**Problem:** Other errno values (e.g., EPROTONOSUPPORT=93, EBADF=9, ETIMEDOUT=110) had no cached objects. We needed to construct arbitrary errno errors.

**Solution:** Use `go:itab.syscall.Errno,error` — the interface table pointer for the `syscall.Errno` type implementing the `error` interface. With this itab, any `syscall.Errno` value can be wrapped.

**Critical detail:** `syscall.Errno` methods are defined with pointer receivers (`func (e *Errno) Error() string`). This means the interface data word must be a **pointer to the Errno value**, not the inline value. Allocate a persistent 8-byte slot per errno:

```javascript
var _errnoDataCache = {};
function goErrFromErrno(errno) {
    if (goErrnoItab) {
        if (!_errnoDataCache[errno]) {
            var slot = Memory.alloc(8);   // persistent allocation
            slot.writeU64(errno);          // write errno value
            _errnoDataCache[errno] = slot;
        }
        return { itab: goErrnoItab, data: _errnoDataCache[errno] };
    }
    // fallback to pre-cached symbols...
}
```

**Without this fix:** Constructing errors with `context.rcx = errno` (raw integer) caused `panic: nil pointer dereference` inside Go's error `Error()` method, because it tried to dereference the errno integer as a pointer.

---

### 2.6 findLdpSym — Versioned Soname

**Problem:** After `Module.load('/path/to/libvcl_ldpreload.so')`, Frida registers the module under its **versioned soname**: `libvcl_ldpreload.so.26.06`. Calling `Process.findModuleByName('libvcl_ldpreload.so')` returns `null`.

**Fix:** Enumerate all modules and search for `ldpreload` as a substring:

```javascript
function findLdpSym(symName) {
    var mod = null;
    Process.enumerateModules().some(function(m) {
        if (m.name.indexOf('ldpreload') !== -1 || m.path.indexOf('ldpreload') !== -1) {
            mod = m; return true;
        }
        return false;
    });
    ...
}
```

---

### 2.7 connect — EINPROGRESS Handling

**Problem:** VCL `socket()` creates a non-blocking socket (`VCL_SESS_ATTR_NONBLOCK`). Therefore `ldp.connect()` returns `EINPROGRESS` immediately. Previous attempts to handle this were:

#### Attempt A: SO_ERROR polling loop
```javascript
while (soErr === 115 && maxIter-- > 0) {
    ldp.getsockopt(fd, SOL_SOCKET, SO_ERROR, ...);
    soErr = errBuf.readInt();
}
```
**Failed because:** `VPPCOM_ATTR_GET_ERROR` is a VPP stub that **always returns 0** regardless of session state (marked `#VPP-TBD#` in source). So the loop exited in one iteration with `soErr=0`, but the VCL session was still `VCL_STATE_UPDATED` (connecting).

#### Attempt B: ldp.poll(POLLOUT, 5000ms)
```javascript
var pr = ldp.poll(pfd, 1, 5000);
```
**Failed because:** `ldp.poll()` is a blocking call. When called from Frida's `onLeave` hook, it freezes the Frida JS thread entirely. Since the Frida JS thread is shared across ALL hooks, no other hooks can fire while `ldp.poll` is blocking. This causes a deadlock:
- Frida JS thread frozen in `ldp.poll` waiting for VCL "connected" event
- VCL needs to process events (via message queue drain) to fire POLLOUT
- Event processing may require running code that triggers other hooks
- → **Deadlock**

#### Final fix (Session 2): Return success immediately after EINPROGRESS
```javascript
if (ret === -1 && (e === 115 || e === 114)) {
    // VCL SO_ERROR is always 0 (stub). ldp.poll blocks the JS thread.
    // Return success immediately: VCL session handshake completes async.
    // read/write EAGAIN retries handle the not-yet-connected window.
    ret = 0;
}
```

**Rationale:** After `ldp.connect()` returns EINPROGRESS:
1. VPP receives the SYN and processes it asynchronously
2. The VCL session transitions: `UPDATED → READY` when VPP confirms
3. During this window, `ldp.read()` returns EAGAIN
4. Our read hook retries on EAGAIN until data arrives
5. By the time Go's application-level `Write()` fires the first real data, the VCL session is already READY

This is valid because VPP's loopback is effectively instantaneous for local connections.

> **Session 3 update:** This approach was found to be insufficient — see Section 2.8 for the real fix using `ldp.epoll_wait()`.

---

## Session 3 Fixes

### 2.8 VCL Message Queue Starvation (Root Cause of ENOTCONN/EAGAIN Forever)

**Problem:** After fixing connect to return success on EINPROGRESS, the client's `write()` call returned `ENOTCONN` (107) and `read()` returned `EAGAIN` (11) forever, even though VPP had completed the TCP handshake.

**Root cause:** `vppcom_session_write()` and `vppcom_session_read()` do **NOT** process the VCL worker message queue. When VPP completes a handshake, it puts a `SESSION_CONNECTED` event in the MQ. Without calling a function that drains the MQ, this event sits unread forever — the VCL session stays in `VCL_STATE_UPDATED` and never transitions to `VCL_STATE_READY`.

```
VPP completes handshake
  → Puts SESSION_CONNECTED in VCL worker MQ
  → MQ sits unread because:
     • ldp.write() → vppcom_session_write() → checks session state → ENOTCONN (not READY)
     • ldp.read()  → vppcom_session_read()  → checks session state → EAGAIN
     • Neither function processes the MQ!
  → Session stuck in VCL_STATE_UPDATED forever
```

**Discovery:** Traced through VPP source code:
- `vppcom_session_write()` calls `vcl_session_write_ready()` which just checks `session->session_state`
- `vppcom_session_read()` calls `vcl_session_read_ready()` — same pattern
- Neither calls `vcl_select_handle_mq()` or any MQ drain function
- Only `vppcom_epoll_wait()` processes the MQ via `vcl_epoll_wait_handle_mq()`

**Fix: Use `ldp.epoll_wait()` as a MQ pump.** LDP's `epoll_wait()` calls `vppcom_epoll_wait()` which processes the VCL message queue. Create a temporary epoll fd, add the target fd, and wait:

```javascript
// connect hook — wait for session READY after EINPROGRESS
if (ret === -1 && (e === 115 || e === 114)) {
    console.log('[dbg] connect EINPROGRESS → using LDP epoll to wait for READY');
    var epfd = ldp.epoll_create1(0);
    if (epfd >= 0) {
        var ev = Memory.alloc(12);
        ev.writeU32(0x04); // EPOLLOUT
        ev.add(4).writeU32(this._fd);
        var ctlRet = ldp.epoll_ctl(epfd, 1 /*EPOLL_CTL_ADD*/, this._fd, ev);
        if (ctlRet === 0) {
            var events = Memory.alloc(12);
            var n = ldp.epoll_wait(epfd, events, 1, 5000); // 5s timeout
            // n > 0 → POLLOUT fired → session transitioned to READY
        }
        ldp.close(epfd);
    }
    retval.replace(0);
    this.context.rbx = ptr(0);
    this.context.rcx = ptr(0);
    return;
}
```

**Same pattern applied to read and write hooks:**

```javascript
// read hook — EAGAIN on VCL fd → epoll_wait for EPOLLIN
var ret = ldp.read(fd, buf, len);
if (ret === -1 && getCErrno() === 11 && fd >= 32) {
    var epfd = ldp.epoll_create1(0);
    if (epfd >= 0) {
        var ev = Memory.alloc(12);
        ev.writeU32(0x01); // EPOLLIN
        ev.add(4).writeU32(fd);
        ldp.epoll_ctl(epfd, 1, fd, ev);
        var events = Memory.alloc(12);
        var n = ldp.epoll_wait(epfd, events, 1, 5000);
        ldp.close(epfd);
        if (n > 0) { ret = ldp.read(fd, buf, len); }
    }
}
```

```javascript
// write hook — EAGAIN/ENOTCONN on VCL fd → epoll_wait for EPOLLOUT
var ret = ldp.write(fd, buf, len);
var e = getCErrno();
if (ret === -1 && (e === 11 || e === 107) && fd >= 32) {
    var epfd = ldp.epoll_create1(0);
    if (epfd >= 0) {
        var ev = Memory.alloc(12);
        ev.writeU32(0x04); // EPOLLOUT
        ev.add(4).writeU32(fd);
        ldp.epoll_ctl(epfd, 1, fd, ev);
        var events = Memory.alloc(12);
        var n = ldp.epoll_wait(epfd, events, 1, 5000);
        ldp.close(epfd);
        if (n > 0) { ret = ldp.write(fd, buf, len); }
    }
}
```

**Key insight:** For ANY blocking VCL I/O from the Frida JS thread, use `ldp.epoll_create1()` → `ldp.epoll_ctl(ADD)` → `ldp.epoll_wait()` to process the VCL MQ. This is non-blocking from the perspective of Frida's event loop (it returns when the event fires or times out) and correctly processes all pending MQ events.

---

### 2.9 IPv4/IPv6 Mismatch — "connect failed! no route"

**Problem:** Even with all VCL fixes in place, the client's connect returned "connect failed! no route" from VPP.

**Root cause:** Go's `net.Listen("tcp", "0.0.0.0:9876")` creates an AF_INET6 socket and binds to `[::]:9876`. The client's `net.Dial("tcp", "127.0.0.1:9876")` creates an AF_INET socket. VPP's session lookup table does not match IPv4 connect requests against IPv6 listeners.

```
Server: socket(AF_INET6) → bind([::]:9876) → listen()
  VPP creates listener with transport endpoint: [::]:9876 (IPv6)

Client: socket(AF_INET) → connect(127.0.0.1:9876)
  VPP looks for listener matching 127.0.0.1:9876 (IPv4)
  → No match! IPv6 [::]:9876 ≠ IPv4 127.0.0.1:9876
  → "connect failed! no route"
```

**Fix:** Use `"tcp4"` in both Go binaries to force IPv4:

```go
// echo_server.go
ln, err := net.Listen("tcp4", addr)

// echo_client.go
conn, err := net.Dial("tcp4", addr)
```

This ensures both create AF_INET sockets and VPP's session lookup matches correctly.

---

### 2.10 Go Runtime Poller Bypasses LDP

**Problem:** An earlier Session 3 attempt tried to pass EINPROGRESS back to Go and let Go's runtime poller handle the async connect. This caused an infinite `getsockopt(SO_ERROR)` polling loop.

**Root cause:** Go's runtime poller (`runtime/netpoll_epoll.go`) uses raw syscalls for `epoll_create1`, `epoll_ctl`, and `epoll_pwait` — not libc functions:

```go
// Go runtime source:
func netpollinit() {
    epfd, errno = syscall.EpollCreate1(syscall.EPOLL_CLOEXEC)  // → raw SYSCALL
}
func netpollopen(fd uintptr, pd *pollDesc) uintptr {
    syscall.EpollCtl(epfd, ...)  // → raw SYSCALL, bypasses LDP
}
```

Since LDP's `LD_PRELOAD` only intercepts libc functions, Go's raw `epoll_ctl(ADD, fd=32)` goes to the kernel. The kernel doesn't know about fd=32 (VCL fake fd) → `EBADF`. Go falls back to a busy-polling loop calling `getsockopt(SO_ERROR)` which our hook redirects to VCL → always returns 0 (VPP stub) → infinite loop.

**Conclusion:** Cannot pass EINPROGRESS to Go for VCL fds. All async connect waiting must be handled entirely in the Frida JS hook using `ldp.epoll_*` functions.

---

## 3. Flowcharts

### 3.1 Overall Interception Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Go Binary (echo_server)                          │
│                                                                         │
│  net.Listen("tcp", ":9876")                                             │
│       │                                                                 │
│       ▼                                                                 │
│  syscall.socket(AF_INET6, SOCK_STREAM, 0)   ← Go ABI: rax=10,rbx=1,rcx=0
│       │ addr=0x48ff40                                                   │
│       │                                                                 │
│  ┌────┴────────────────────────────────────────────────────────────┐   │
│  │              Frida Interceptor (interceptor_server.js)           │   │
│  │                                                                  │   │
│  │  Interceptor.replace(0x48ff40, ret_trampoline)                  │   │
│  │  Interceptor.attach(0x48ff40, {                                 │   │
│  │    onEnter: save rax→_domain, rbx→_type, rcx→_protocol         │   │
│  │    onLeave: call ldp.socket(_domain, _type, _protocol)          │   │
│  │             setGoReturn(rax=fd, rbx=0, rcx=0)                  │   │
│  │  })                                                              │   │
│  └───────────────────────────┬──────────────────────────────────────┘  │
│                               │                                         │
└───────────────────────────────┼─────────────────────────────────────────┘
                                │
                                ▼
              ┌─────────────────────────────────┐
              │  libvcl_ldpreload.so (LDP/VCL)  │
              │                                 │
              │  ldp_socket() {                 │
              │    vlsh = vls_create(TCP)        │
              │    fd = vlsh + 32               │
              │    return fd                    │
              │  }                              │
              └──────────────┬──────────────────┘
                             │
                             ▼
              ┌──────────────────────────────────┐
              │         VPP (vpp process)         │
              │                                  │
              │  Creates VCL session              │
              │  Returns session handle (vlsh=0) │
              └──────────────────────────────────┘
```

### 3.2 VCL Fake FD Dispatch

```
 Go Runtime                  LDP                      VCL/VPP
     │                        │                          │
     │ read(fd=33, buf, len)  │                          │
     │──────────────────────→ │                          │
     │                        │  fd < 32?                │
     │                        │  NO (fd=33≥32)           │
     │                        │  vlsh = fd - 32 = 1      │
     │                        │  vls_read(vlsh=1, ...)   │
     │                        │─────────────────────────→│
     │                        │  (EAGAIN if not ready)   │
     │                        │←─────────────────────────│
     │                        │  retry loop...           │
     │                        │  (when READY: data)      │
     │                        │←─────────────────────────│
     │ n bytes                │                          │
     │←──────────────────────  │                          │
     │                        │                          │
     │ close(fd=5, ...)        │                          │
     │──────────────────────→ │                          │
     │                        │  fd < 32?                │
     │                        │  YES (fd=5)              │
     │                        │  libc_close(5)           │
     │                        │────────────────→ kernel  │
     │                        │                          │
```

### 3.3 accept4 Blocking — Epoll Avoidance

```
BEFORE FIX (non-blocking accept4):

Go net.(*FD).Accept()
    │
    ├─ syscall.accept4(listenFd, ...) → EAGAIN (no connection yet)
    │
    ├─ internal/poll.(*FD).Init(connFd)
    │     └─ epoll_ctl(ADD, connFd=33, ...)  ← KERNEL: fd=33 not real → EBADF
    │
    └─ Returns error: "accept4: bad file descriptor"


AFTER FIX (blocking accept4 in Frida hook):

Go net.(*FD).Accept()
    │
    ├─ syscall.accept4(listenFd, ...)
    │       ↑ Frida hook spin-waits until ldp.accept4() returns real connection
    │       │  (retries on EAGAIN with 1ms sleep)
    │       │
    │       ← Returns connFd=33 immediately (blocking semantics)
    │
    ├─ internal/poll.(*FD).Init(connFd=33)
    │     └─ (Go sees blocking accept → does NOT call epoll_ctl)
    │
    └─ Returns connFd=33 successfully ✓
```

### 3.4 MPTCP Rejection Flow

```
Go net.Listen("tcp", ":9876")
    │
    ├─ [Go 1.21+] socket(AF_INET6, SOCK_STREAM, IPPROTO_MPTCP=262)
    │       │
    │       └─ Frida socket hook onLeave:
    │               protocol==262?  YES
    │               → retval.replace(-1)
    │               → rbx = goErrFromErrno(93).itab  ← EPROTONOSUPPORT
    │               → rcx = goErrFromErrno(93).data
    │               Go gets error: "protocol not supported"
    │               Go falls back to regular TCP ✓
    │
    └─ socket(AF_INET6, SOCK_STREAM, 0)   ← normal TCP
            │
            └─ ldp.socket(10, 1, 0) → fd=32  ✓
```

### 3.5 Go Error Interface Construction

```
Go error interface layout (16 bytes):
┌──────────────┬──────────────┐
│  itab_ptr    │  data_ptr    │
│  (8 bytes)   │  (8 bytes)   │
└──────────────┴──────────────┘

For syscall.Errno (pointer receiver methods):
  itab_ptr → go:itab.syscall.Errno,error  (found in Go binary by symbol name)
  data_ptr → pointer to a uintptr holding the errno value

Example: errno=9 (EBADF):
  slot = Memory.alloc(8)    // 8-byte allocation
  slot.writeU64(9)           // write errno=9
  error = { itab: goErrnoItab, data: slot }

WRONG approach (causes nil pointer panic):
  error = { itab: goErrnoItab, data: ptr(9) }  // 9 is not a valid pointer!
  // When Go calls error.Error(), it dereferences data as *syscall.Errno
  // ptr(9) is not a valid memory address → SEGFAULT/panic
```

### 3.6 Full Server Startup Flow

```
frida ./test/echo_server -l interceptor_server.js
    │
    ├─ Frida spawns echo_server, pauses at entry
    │
    ├─ interceptor_server.js executes:
    │   ├─ Find Go symbols (syscall.socket, bind, listen, ...)
    │   ├─ Module.load(libvcl_ldpreload.so)
    │   │     └─ VCL connects to VPP via /run/vpp/app_ns_sockets/default
    │   ├─ Create ldp NativeFunctions (ldp.socket, ldp.bind, ...)
    │   ├─ Find go:itab.syscall.Errno,error
    │   └─ Install hooks (Interceptor.replace + Interceptor.attach for each syscall)
    │
    ├─ Frida resumes echo_server
    │
    ├─ Go: net.Listen("tcp", ":9876")
    │   │
    │   ├─ socket(AF_INET6, SOCK_STREAM, IPPROTO_MPTCP=262)
    │   │   └─ HOOK: reject → EPROTONOSUPPORT → Go retries with proto=0
    │   │
    │   ├─ socket(AF_INET6, SOCK_STREAM, 0)
    │   │   └─ HOOK: ldp.socket(10, 0x80801, 0) → fd=32 (VCL session 0)
    │   │
    │   ├─ setsockopt(32, SOL_SOCKET, SO_REUSEADDR, 1)
    │   │   └─ HOOK: ldp.setsockopt(32, 1, 2, &1, 4) → 0
    │   │
    │   ├─ bind(32, [::]:9876, 28)
    │   │   └─ HOOK: ldp.bind(32, addr, 28) → 0
    │   │
    │   ├─ getsockname(32, ...) → [::]:9876
    │   │   └─ HOOK: ldp.getsockname(32, ...) → 0
    │   │
    │   └─ Listen(32, 4096)
    │       └─ HOOK:
    │           ├─ setsockopt(32, IPPROTO_IPV6, IPV6_V6ONLY, 1)  ← disable dual-stack
    │           └─ ldp.listen(32, 4096) → 0
    │               └─ VPP: creates TCP listener on port 9876
    │
    └─ Server prints: "[server] Listening. Waiting for connections..."
            │
            ▼
       accept4(32, addr, addrlen, SOCK_CLOEXEC)
            └─ HOOK: spin-wait on ldp.accept4(...) until client connects
```

### 3.7 Full Client Connect Flow

```
frida -f ./test/echo_client -l interceptor_client.js -- 127.0.0.1:9876 "hello vcl"
    │
    ├─ VCL connects to VPP
    ├─ Hooks installed
    │
    ├─ Go: net.Dial("tcp4", "127.0.0.1:9876")
    │   │
    │   ├─ socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP=262)
    │   │   └─ HOOK: reject → EPROTONOSUPPORT
    │   │
    │   ├─ socket(AF_INET, SOCK_STREAM, 0)
    │   │   └─ HOOK: ldp.socket(2, 0x80801, 0) → fd=32 (VCL session 0)
    │   │
    │   └─ connect(32, 127.0.0.1:9876, 16)
    │       └─ HOOK:
    │           ├─ ldp.connect(32, addr, 16)
    │           │   → VPP receives SYN
    │           │   → returns EINPROGRESS (VCL_STATE_UPDATED)
    │           ├─ EINPROGRESS → ldp.epoll_create1() + epoll_ctl(EPOLLOUT)
    │           ├─ ldp.epoll_wait(5s) → processes VCL MQ
    │           │   → SESSION_CONNECTED event consumed
    │           │   → session transitions to VCL_STATE_READY
    │           │   → POLLOUT fires, n=1
    │           └─ return 0 to Go ✓
    │
    ├─ [Server side] accept4 spin-wait returns fd=33 (VCL conn session)
    │   └─ Go server: starts conn handler goroutine
    │
    ├─ Go client: write("hello vcl\n")
    │   └─ HOOK: ldp.write(32, ...) → 10 bytes ✓
    │       (session already READY from connect epoll_wait)
    │
    ├─ [Server side] read(33, buf, 4096)
    │   └─ HOOK: ldp.read(33, buf, 4096) → 10 bytes ("hello vcl\n")
    │
    ├─ [Server side] write(33, "Echo: hello vcl\n", ...)
    │   └─ HOOK: ldp.write(33, ...) → bytes written
    │
    ├─ Go client: read(32, buf, 4096)
    │   └─ HOOK: ldp.read(32, ...) → EAGAIN
    │       ├─ epoll_create1() + epoll_ctl(EPOLLIN) + epoll_wait(5s)
    │       │   → MQ drained, data-available event consumed
    │       ├─ ldp.read(32, ...) → bytes read ✓
    │       └─ return to Go
    │
    └─ Client prints: "[client] Echo: hello vcl"
                      "[client] Done."
```

---

## 4. Scripts Changed

### Session 2: `interceptor_server.js` Changes

| Change | Reason |
|--------|--------|
| Added `syscall.read`, `syscall.write`, `syscall.Close` to `syscallNames` | Route VCL fake fds through LDP |
| Added `read`, `write`, `close` to `ldp` object | Ditto |
| Added `hookRead()` with EAGAIN retry loop | Blocking read for VCL sessions |
| Added `hookWrite()` | Route writes through LDP |
| Added `hookClose()` | Route close through LDP |
| Socket onLeave: reject proto=262 (MPTCP) | Prevent duplicate listener EADDRINUSE |
| Listen onLeave: setsockopt(IPV6_V6ONLY=1) | Prevent dual-stack EADDRINUSE |
| accept4 onLeave: spin-wait on EAGAIN | Prevent Go from using epoll on fake fds |
| connect onLeave: treat EINPROGRESS as success | Avoid blocking JS thread in ldp.poll |
| goErrFromErrno: use go:itab.syscall.Errno,error + heap slot | Support arbitrary errno values |
| findLdpSym: substring search for 'ldpreload' | Handle versioned soname `libvcl_ldpreload.so.26.06` |

### Session 2: `interceptor_client.js` Changes

| Change | Reason |
|--------|--------|
| Added `syscall.read`, `syscall.write`, `syscall.Close` to `syscallNames` | Same as server |
| Added `read`, `write`, `close` to `ldp` object | Same as server |
| Added `hookRead()`, `hookWrite()`, `hookClose()` functions | Same as server |
| connect onLeave: treat EINPROGRESS as success | Same as server |

### Session 3: `interceptor_client.js` Changes

| Change | Reason |
|--------|--------|
| Added `epoll_create1`, `epoll_ctl`, `epoll_wait` to `ldp` object | MQ pump for VCL sessions |
| connect onLeave: epoll_wait(EPOLLOUT) after EINPROGRESS | Wait for session READY via MQ processing |
| read onLeave: epoll_wait(EPOLLIN) on EAGAIN for VCL fds | Process MQ to receive data-available events |
| write onLeave: epoll_wait(EPOLLOUT) on EAGAIN/ENOTCONN for VCL fds | Process MQ for writability on VCL fds |

### Session 3: `echo_server.go` and `echo_client.go` Changes

| Change | Reason |
|--------|--------|
| `net.Listen("tcp", addr)` → `net.Listen("tcp4", addr)` | Force IPv4 — VPP can't match IPv4 connect to IPv6 listener |
| `net.Dial("tcp", addr)` → `net.Dial("tcp4", addr)` | Force IPv4 — same mismatch issue |

---

## 5. Remaining Issues / Known Limitations

### 5.1 VPP VCL Worker Registration from Frida JS Thread

When LDP functions are called from Frida's `onLeave` handler, they execute on the Frida JS thread. VCL registers OS threads as "VCL workers" via `vls_register_vcl_worker()`. This means the Frida JS thread becomes a VCL worker. Go's goroutines run on multiple OS threads — if a syscall hook fires on a different OS thread, VCL creates a new worker and may exhibit multi-threaded session access bugs.

**Mitigation:** VCL has `vls_mt_detect()` to detect multi-threaded access, but session cloning under MT can still cause EADDRINUSE on the accept path.

### 5.2 Blocking Hooks Freeze Frida JS Thread

Any LDP function called from `onLeave` that blocks freezes the Frida JS event loop. Current approach:
- **accept4 (server)**: spin-wait with 1ms sleep on EAGAIN (acceptable — Go only calls accept4 once per connection)
- **connect (client)**: `ldp.epoll_wait(EPOLLOUT, 5s)` — blocks until session READY, but processes MQ correctly
- **read (client/server)**: `ldp.epoll_wait(EPOLLIN, 5s)` on EAGAIN for VCL fds — blocks until data available
- **write (client/server)**: `ldp.epoll_wait(EPOLLOUT, 5s)` on EAGAIN/ENOTCONN for VCL fds

### 5.3 VPPCOM_ATTR_GET_ERROR Stub

`getsockopt(SO_ERROR)` on a VCL fd always returns 0 regardless of actual session state. This makes the standard "poll SO_ERROR for connect completion" pattern impossible. The workaround (epoll_wait for POLLOUT) correctly processes the MQ.

### 5.4 IPv4 Only

Both Go binaries must use `"tcp4"` to force IPv4. VPP's session lookup does not match IPv4 connect requests against IPv6 listeners. This means dual-stack operation is not currently supported.

### 5.5 Go Runtime Poller Incompatibility

Go's runtime poller uses raw syscalls (`epoll_create1`, `epoll_ctl`, `epoll_pwait`) that bypass LDP's LD_PRELOAD. VCL fake fds cannot be registered with the kernel's epoll. All async I/O waiting must be handled in Frida hooks, not delegated to Go's runtime.

---

## 6. Verified Working — Full E2E Echo Test

**Session 3** — complete end-to-end echo test verified:

### Client log (`/tmp/client_final2.log`):
```
Spawning `./test/echo_client 127.0.0.1:9876 hello vcl`...
[+] Found syscall.read at 0x4907c0
vppcom_app_init_common:1569: vcl<116299:0>: app_name 'echo_client-ldp-116299', my_client_index 1 (0x1)
[+] All client hooks installed. Go syscalls will be redirected to VCL.
[client] Connecting to 127.0.0.1:9876
[+] socket succeeded: ret=32
[>] connect(32, 0xc00001e14c, 16)
[dbg] connect EINPROGRESS → using LDP epoll to wait for READY
[dbg] epoll_ctl(ADD, fd=32) = 0
vcl_session_connected_handler:511: vcl<116299:0>: session 0 [0x2] connected
[dbg] epoll_wait returned n=1
[dbg] POLLOUT fired — session READY
[client] Connected.
[>] write(fd=32, len=10)
[+] write succeeded: ret=10
[client] Echo: hello vcl
[client] Done.
```

### Server log (`/tmp/server3.log`):
```
[server] Listening. Waiting for connections...
vppcom_session_accept:2087: vcl<113899:0>: accepted session 4 [0x3] peer: 0.0.0.0:0 local: 0.0.0.0:9876
[server] Accepted connection from 0.0.0.0:0
[+] accept4 succeeded: ret=33
[+] read succeeded: ret=10
[+] write succeeded: ret=44
```

### Confirmed:
- ✅ VCL session created and connected via epoll_wait MQ pump
- ✅ Client write over VCL session (10 bytes)
- ✅ Server read + echo write over VCL session
- ✅ Client read echo response via epoll_wait EPOLLIN
- ✅ Client prints `[client] Echo: hello vcl` and `[client] Done.`

---

## 7. Test Commands

```bash
# 0. Set LD_LIBRARY_PATH
export VPP_LIB=/home/aritrbas/vpp/build-root/install-vpp_debug-native/vpp/lib/x86_64-linux-gnu
export LD_LIBRARY_PATH=$VPP_LIB

# 1. Start VPP
echo 'PASSWORD' | sudo -S /path/to/vpp \
  "unix { nodaemon log /tmp/vpp.log full-coredump } \
   api-trace { on } \
   session { enable use-app-socket-api }" >/dev/null 2>&1 &
sleep 6 && echo 'PASSWORD' | sudo -S chmod o+w /run/vpp/app_ns_sockets/default

# 2. Start server
VCL_CONFIG=/tmp/server-share/vcl.conf \
  frida ./test/echo_server -l interceptor_server.js </dev/null >/tmp/server.log 2>&1 &
sleep 8 && grep "Listening" /tmp/server.log

# 3. Run client (one-shot mode — avoids Frida REPL stealing stdin)
VCL_CONFIG=/tmp/client-share/vcl.conf \
  frida -f ./test/echo_client -l interceptor_client.js \
  -- 127.0.0.1:9876 "hello vcl" </dev/null >/tmp/client.log 2>&1

# 4. Check results
grep -E "Echo|Done|error|Error|succeeded|connect|READY" /tmp/client.log
grep -E "Accept|read|write|close|error" /tmp/server.log | tail -20
```
