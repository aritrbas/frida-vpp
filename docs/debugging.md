# Debugging & Development History

**Date range:** April 2026  
**Goal:** Intercept Go socket syscalls and redirect them to VPP's VCL library using Frida.  
**Final status:** ✅ End-to-end working for TCP echo and HTTP (client↔server) over VPP VCL.

This document consolidates all failed experimental attempts, debugging sessions, and bug fixes into a single chronological reference. It covers:

1. The experimental interceptor attempts (`experiments/`) and why each failed
2. Session 2 & 3 debugging of the working interceptors (`interceptor_server.js`, `interceptor_client.js`)
3. Final unification into `interceptor.js`

For the working architecture, see [interceptor_architecture.md](interceptor_architecture.md).  
For ABI-level register analysis, see [abi_analysis.md](abi_analysis.md).

---

## Part 1: The Core Problem

The goal is to intercept network syscalls (`socket`, `bind`, `listen`, `accept4`, `connect`, `setsockopt`, `getsockopt`, `getsockname`, `read`, `write`, `close`) in a **Go binary** and redirect them to VPP's VCL library (`libvcl_ldpreload.so`) using Frida.

This is fundamentally difficult because:

1. **Go bypasses libc entirely** — Go's runtime calls the kernel directly via `SYSCALL` instruction through `runtime/internal/syscall.Syscall6`. There are no PLT/GOT entries for `socket`, `bind`, etc. `LD_PRELOAD` has nothing to intercept.
2. **Go uses a different calling convention** (Go ABI) than C libraries (System V AMD64 ABI). Registers carry arguments in different positions.
3. **Go's return convention** differs — syscalls return `(r1, r2, errno)` in `(rax, rbx, rcx)`, not just `rax`.

---

## Part 2: Experimental Attempts (All Failed)

Each file in `experiments/` represents a different approach to solving the interception problem. All failed, but each contributed insights that led to the working solution.

---

### `experiments/interceptor2.js` — Hooking libc Symbols

**Approach:**
- Loads `libvcl_ldpreload.so` into the process via `Module.load()`.
- Finds libc symbols (`socket`, `bind`, `listen`, `select`, `setsockopt`, `getsockname`) using `Module.findExportByName(null, 'socket')`.
- Uses `Interceptor.replace()` to replace each libc symbol with the corresponding VCL function.
- Attaches logging via `Interceptor.attach()`.

**Why It Fails:**
- `Module.findExportByName(null, 'socket')` resolves to `socket` in `libc.so.6`.
- **Go never calls libc's `socket()`**. The Go runtime issues syscalls directly:
  ```
  syscall.socket → syscall.RawSyscall → runtime/internal/syscall.Syscall6 → SYSCALL instruction
  ```
- The Frida hooks on libc symbols **never fire** because Go's code path never touches them.
- Even if they did fire, `args[0]`, `args[1]`, etc. in Frida's `onEnter` reflect System V ABI register positions (`rdi`, `rsi`, `rdx`), but Go places arguments in `rax`, `rbx`, `rcx` — so arguments would be read as garbage.

**Verdict:** ❌ Completely wrong interception target. Hooks never fire.

---

### `experiments/interceptor3.js` — Replacing Go Symbols with LDP Functions Directly

**Approach:**
- Uses `Module.enumerateSymbols('test_server_go')` to find Go symbols like `syscall.socket`, `syscall.bind`, etc.
- Finds VCL functions from `libvcl_ldpreload.so`.
- Uses `Interceptor.replace(originalSocket, new NativeFunction(vclSocket, 'int', ['int','int','int']))` — directly replacing the Go function entry point with the C VCL function.

**Why It Fails:**
- **ABI mismatch.** When Go calls `syscall.socket(domain, type, protocol)`, the arguments arrive in Go ABI registers (`rax`, `rbx`, `rcx`). But the VCL `socket()` function reads arguments from System V positions (`rdi`, `rsi`, `rdx`). VCL reads **garbage** from `rdi/rsi/rdx`.
- The `Interceptor.attach()` after `Interceptor.replace()` hooks the **trampoline**, not the original code. `args[0]` etc. read from `rdi/rsi/rdx` which are empty/wrong.

**Verdict:** ❌ Correct interception target, but ABI mismatch causes garbage arguments.

---

### `experiments/interceptor4.js` — Raw Syscall Interception at `syscall.RawSyscall6`

**Approach:**
- Hooks `syscall.RawSyscall6` — the single Go function that funnels **all** syscalls.
- Reads `args[0]` (which Frida maps to `rdi`) as the syscall number.
- Uses a switch statement on the syscall number to identify which syscall is being made.

**Why It Fails:**
- **Wrong register mapping.** `args[0]` in Frida's `onEnter` maps to the `rdi` register (System V convention). But at the entry of `syscall.RawSyscall6`, the Go ABI places `rax` = syscall number, `rbx` = arg1, etc. So `args[0].toInt32()` reads `rdi` which is **arg3** of the syscall, not the syscall number.
- Even if the syscall number were correctly identified, there's no mechanism to redirect the call to VCL.

**Verdict:** ❌ Wrong register indexing. Even correct identification wouldn't solve the redirection problem.

---

### `experiments/interceptor_v1.js` — The prepRegs Shim Approach (Most Complete Failed Attempt)

> **Originally:** `interceptor.js` (root level), later `interceptor_full_attempt.js`, now `interceptor_v1.js`

**Approach:**
- Targets Go binary. Enumerates Go symbols for all socket syscalls.
- Loads both `libvcl_ldpreload.so` and `libPrepRegs.so`.
- Uses `prepRegs2.asm` which provides **separate** `prepRegs`, `prepRegs2`...`prepRegs5` functions (identical code but different symbols) so each syscall can be replaced with its own unique trampoline.
- For each syscall:
  1. `Interceptor.replace(originalXxx, prepRegsN)` — redirect to ABI shim
  2. `Interceptor.attach(originalXxx, ...)` — log entry/exit
  3. `Interceptor.attach(prepRegsN, { onLeave })` — after shim, call corresponding LDP function, `retval.replace(ret)`

**Why It Fails:**

1. **Go return value convention not handled.** After every LDP call, `retval.replace(ret)` only sets `rax`. But `rbx` and `rcx` are NOT set — Go interprets non-zero `rcx` as an error.
2. **accept4 is commented out.** The server's accept path still goes to the kernel.
3. **Stack return chain corruption.** `prepRegs` does `ret` to return to Go's caller, but the original function has a different stack layout. Go's stack-split check may trigger `"fatal error: runtime: split stack overflow"`.
4. **No error handling for LDP functions.** When LDP returns `-1`, the C errno isn't translated back into Go return convention.

**Verdict:** ❌ Closest to correct but fatally flawed by return value corruption and missing rbx/rcx cleanup.

---

### `experiments/interceptor_v2.js` — Syscall/RawSyscall6 Level Hooks

> **Originally:** `interceptor2.js` (root level), later `interceptor_syscall_level.js`, now `interceptor_v2.js`

**Approach:**
- Hooks at the `syscall.Syscall`, `syscall.Syscall6`, `syscall.RawSyscall6`, and `runtime/internal/syscall.Syscall6` level.
- Uses `Instruction.parse()` to disassemble Go functions and find specific instruction patterns.
- The `executeCodeRange()` function attempts to extract and re-execute specific code ranges.

**Why It Fails:**
- `Interceptor.attach` on `originalSocket` calls `executeCodeRange()` which is read-only analysis, not interception.
- The Stalker-based approach (commented out) would trace all instructions but doesn't redirect to VCL.
- The `Interceptor.attach` on `originalRawSyscall6` correctly reads `this.context.rax` as the syscall number — but there's no mechanism to prevent the real syscall and redirect to VCL.

**Verdict:** ❌ Mostly diagnostic/exploration code, no actual redirection mechanism.

---

### `experiments/interceptor_server_v1.js` — Server with Global Flag Dispatch

> **Originally:** `interceptor_server.js` (root level)

**Approach:**
- Targets `echo_server` binary.
- Uses a **global flag** (`isPrepRegsFunctionAttached`) to distinguish which syscall is being intercepted.
- All 3-arg syscalls share a single `prepRegsFunction` trampoline.
- In `prepRegsFunction.onLeave`, checks the flag to decide which LDP function to call.
- Includes `handleError()` that reads C errno and sets `rax=-1, rbx=0, rcx=errno`.

**Why It Fails:**

1. **Thread-safety race condition.** `isPrepRegsFunctionAttached` is a global JS variable. Two goroutines calling different syscalls simultaneously race on this flag — goroutine A sets "socket", goroutine B sets "bind", then A's onLeave reads "bind" and calls the wrong LDP function.
2. **Return values still incomplete.** `handleError()` only handles the error case. On **success**, `rbx` and `rcx` are still not set to `0`.
3. **accept4 uses `prepRegs6Function` for a 4-arg call.** The extra mappings read garbage from unused registers.

**Verdict:** ❌ Thread-unsafe global flag, incomplete return value handling.

---

### `experiments/interceptor_client_v1.js` — Client with Global Flag Dispatch

> **Originally:** `interceptor_client.js` (root level)

**Approach:**
- Same architecture as `interceptor_server_v1.js` but targets `echo_client`.
- Adds `getsockopt` and `connect` interception.
- Has a `send()/recv()` pause mechanism for debugging.

**Why It Fails:**
- Same **thread-safety** issue with global flag.
- Same **incomplete return value** handling.
- `connect` returns `EINPROGRESS` for non-blocking sockets — needs special handling not present here.

**Verdict:** ❌ Same fundamental issues as server version.

---

### `experiments/prepRegs.asm` — Basic ABI Shim (3-arg)

```nasm
prepRegs:
    mov rdi, rax    ; Go arg1 → System V arg1
    mov rsi, rbx    ; Go arg2 → System V arg2
    mov rdx, rcx    ; Go arg3 → System V arg3
    xor rax, rax
    xor rbx, rbx
    xor rcx, rcx
    ret
```

Correctly maps 3 Go ABI registers to System V positions and zeros `rax/rbx/rcx`. Also includes `prepRegs6` for 6-arg calls and `updateRegs` for error handling.

**Problem:** Only shuffles registers and returns. Doesn't call the LDP function. The two-step approach (shim shuffles, Frida calls LDP in `onLeave`) leaves return values in a bad state because Frida's `onLeave` runs after the shim returns with zeroed registers.

**Verdict:** ⚠️ Correct register mapping, but the two-step approach is fragile.

---

### `experiments/prepRegs2.asm` — Multiple Named Shims

Provides `prepRegs`, `prepRegs2`...`prepRegs5`, `prepRegs6`, `prepRegs7` — identical register-shuffling code under different symbol names. Created to solve the "single trampoline for multiple syscalls" problem so Frida can `attach` to each separately.

**Verdict:** ⚠️ Correct intent for disambiguation, same return value problem as `prepRegs.asm`.

---

### Summary of Experimental Approaches

| File | Strategy | Primary Failure Mode |
|------|----------|---------------------|
| `interceptor2.js` | Hook libc symbols | Hooks never fire (Go bypasses libc) |
| `interceptor3.js` | Replace Go symbols with LDP directly | ABI mismatch (garbage args) |
| `interceptor4.js` | Hook RawSyscall6 | Wrong register indexing, no redirect |
| `interceptor_v1.js` | Per-syscall prepRegs shims | No rbx/rcx cleanup, accept4 missing |
| `interceptor_v2.js` | Disassembly/Stalker exploration | No redirection mechanism |
| `interceptor_server_v1.js` | Shared shim + global flag | Thread-unsafe, incomplete return values |
| `interceptor_client_v1.js` | Same as server + connect | Thread-unsafe, incomplete return values |
| `prepRegs.asm` | 3-arg ABI shim | Doesn't call LDP, return value undefined |
| `prepRegs2.asm` | Multiple named shims | Same return value problem |

### The Three Unfixed Bugs Across All Attempts

1. **Go Return Value Convention:** Every attempt sets `rax` with `retval.replace(ret)` but fails to set `rbx=0, rcx=0`. Stale values cause Go to interpret successful calls as failures.
2. **Thread Safety:** Global `isPrepRegsFunctionAttached` flag races under Go's concurrent goroutine model.
3. **Blocking Calls in Frida JS:** `accept4` is a blocking call. Calling it from Frida's `onLeave` blocks the entire Frida JS event loop.

---

## Part 3: Working Solution Design (Session 1)

The corrected interceptors (`interceptor_server.js` and `interceptor_client.js`) fix all three bugs:

1. **Return values:** Always set `rbx=0, rcx=0` on success. On error, use `go:itab.syscall.Errno,error` with heap-allocated errno slots for arbitrary errno construction.
2. **Thread safety:** Per-invocation `this._` state instead of global flags.
3. **No assembly shim needed:** `Memory.alloc` + `X86Writer` creates a single `ret` trampoline. Read Go ABI registers in `onEnter`, call LDP in `onLeave`.

This eliminated all the complexity of the prepRegs assembly approach.

---

## Part 4: Session 2 — Bug Fixes for Server + Client

Starting state: `interceptor_server.js` could bring the server to "Listening" status. Remaining bugs:

| # | Bug | Symptom |
|---|-----|---------|
| 1 | `accept4` returned EBADF to Go | `[server] Accept error: accept4: bad file descriptor` |
| 2 | `connect` returned EINPROGRESS stuck in SO_ERROR polling loop | Client stuck forever |
| 3 | No `read`/`write`/`close` hooks in client | Data transfer would fail after connect |

---

### 4.1 LDP Fake FD Numbers (Root Cause of EBADF)

**Discovery:** `ldp.accept4()` returns fake fd numbers. LDP maps VCL session handles to fd numbers using a bit offset:

```c
/* ldp.c */
#define LDP_SID_BIT_MIN  5   /* vlsh_bit_val = (1 << 5) = 32 */
static u32 ldp_vlsh_to_fd(vls_handle_t vlsh) {
    return (vlsh + ldp->vlsh_bit_val);   // fd = vlsh + 32
}
```

So `socket()` returns fd=32, `accept4()` returns fd=33, etc. These are **not kernel fds**.

**Problem flow (before fix):**
```
accept4 hook → ldp.accept4() → returns fd=33 (VCL fake fd)
Go receives fd=33 from accept4 hook
Go calls syscall.read(fd=33, ...) → kernel EBADF (fd 33 doesn't exist in kernel)
Go calls epoll_ctl(epfd, ADD, 33) → kernel EBADF
```

**Fix:** Hook `syscall.read`, `syscall.write`, and `syscall.Close` to route through `ldp.read/write/close`. LDP internally dispatches: fd ≥ 32 → VCL path, fd < 32 → kernel libc path.

---

### 4.2 accept4 EBADF → Go Enters Epoll Path

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

**Fix:** Make accept4 blocking (spin-wait on EAGAIN). When accept4 returns a valid fd immediately, Go never enters the "register with epoll" path.

---

### 4.3 MPTCP (proto=262) Duplicate Listener

**Problem:** Go 1.21+ enables MPTCP by default. It calls `socket(AF_INET6, SOCK_STREAM, IPPROTO_MPTCP=262)` in addition to the regular TCP socket. VPP doesn't support MPTCP but creates a TCP session anyway, causing both sessions to compete for the same port → EADDRINUSE.

**Discovery method:** Added logging to socket `onLeave` showing protocol. Saw `protocol=262`.

**Fix:** Reject proto=262 with `EPROTONOSUPPORT` (errno=93). Go falls back to standard TCP.

---

### 4.4 IPv6 Dual-Stack and EADDRINUSE in listen()

**Problem:** Go binds to `[::]:9876` (IPv6 dual-stack). VPP tries to create BOTH an IPv6 and IPv4 listener → second `listen()` fails with EADDRINUSE.

**Fix:** Set `IPV6_V6ONLY=1` before calling `ldp.listen()` on IPv6 sockets. VPP creates only one listener.

---

### 4.5 Go Error Interface Construction (goErrFromErrno)

**Background:** Go's `error` is a 16-byte interface `{itab_ptr, data_ptr}`. You must use real Go runtime objects.

**Previous approach (broken):** Used `syscall.errEAGAIN`, `syscall.errEINVAL`, `syscall.errENOENT` — pre-cached for only three errno values. Other errnos (EPROTONOSUPPORT=93, EBADF=9) had no cached objects.

**Solution:** Use `go:itab.syscall.Errno,error` — the interface table pointer for `syscall.Errno`. Critical detail: `Errno` uses pointer receivers, so data must be a **pointer to the errno value**. Allocate a persistent 8-byte slot per errno:

```javascript
var _errnoDataCache = {};
function goErrFromErrno(errno) {
    if (!_errnoDataCache[errno]) {
        var slot = Memory.alloc(8);
        slot.writeU64(errno);
        _errnoDataCache[errno] = slot;
    }
    return { itab: goErrnoItab, data: _errnoDataCache[errno] };
}
```

---

### 4.6 findLdpSym — Versioned Soname

**Problem:** After `Module.load('/path/to/libvcl_ldpreload.so')`, Frida registers the module under its versioned soname (`libvcl_ldpreload.so.26.06`). `Process.findModuleByName('libvcl_ldpreload.so')` returns `null`.

**Fix:** Search all modules for `ldpreload` as a substring.

---

### 4.7 connect — EINPROGRESS Handling

VCL sockets are non-blocking. `ldp.connect()` returns `EINPROGRESS` immediately. Multiple approaches were tried:

#### Failed: SO_ERROR Polling Loop
```javascript
while (soErr === 115 && maxIter-- > 0) {
    ldp.getsockopt(fd, SOL_SOCKET, SO_ERROR, ...);
    soErr = errBuf.readInt();
}
```
**Failed because:** `VPPCOM_ATTR_GET_ERROR` is a VPP stub that **always returns 0** regardless of session state (marked `#VPP-TBD#` in VPP source). The loop exited immediately with `soErr=0`, but VCL was still connecting.

#### Failed: ldp.poll(POLLOUT, 5000ms)
```javascript
var pr = ldp.poll(pfd, 1, 5000);
```
**Failed because:** `ldp.poll()` is a blocking call. Frida's JS engine runs all hooks on a single thread. Calling `ldp.poll(5000ms)` froze the entire Frida JS event loop, creating a deadlock — the server's accept4 spin-wait was also frozen.

#### Failed: Return Success Immediately
Return success after EINPROGRESS, let read/write hooks spin-wait on EAGAIN. **Failed because** `vppcom_session_read/write()` do NOT process the VCL worker message queue. `SESSION_CONNECTED` sat unread forever.

#### Working Fix: ldp.epoll_wait() as MQ Pump
See Session 3 (Section 5.1).

---

### Session 2 Failed Approaches Summary

| Attempt | Strategy | Why It Failed |
|---------|----------|---------------|
| SO_ERROR polling | `VPPCOM_ATTR_GET_ERROR` always returns 0 (VPP stub) | Abandoned after 50000 iterations |
| `ldp.poll(POLLOUT)` | Blocks Frida JS thread → deadlock with accept4 | Server and client both frozen |
| `ptr(errno)` as Go error data | `syscall.Errno` has pointer receivers; raw int → SEGFAULT | panic/segfault in error formatting |
| Exact module name lookup | Module registered under versioned SONAME `.so.26.06` | `null` module, LDP functions fail |

---

## Part 5: Session 3 — VCL Message Queue Starvation & Final Fixes

---

### 5.1 VCL Message Queue Starvation (Root Cause of ENOTCONN/EAGAIN Forever)

**Problem:** After fixing connect to return success on EINPROGRESS, the client's `write()` returned `ENOTCONN` (107) and `read()` returned `EAGAIN` (11) forever, even though VPP had completed the TCP handshake.

**Root cause:** `vppcom_session_write()` and `vppcom_session_read()` do **NOT** process the VCL worker message queue. When VPP completes a handshake, it posts `SESSION_CONNECTED` to the MQ. Without draining the MQ, the session stays in `VCL_STATE_UPDATED` forever.

```
VPP completes handshake
  → Puts SESSION_CONNECTED in VCL worker MQ
  → MQ sits unread because:
     • ldp.write() → vppcom_session_write() → checks state → ENOTCONN
     • ldp.read()  → vppcom_session_read()  → checks state → EAGAIN
     • Neither function processes the MQ!
  → Session stuck in VCL_STATE_UPDATED forever
```

**Fix:** Use `ldp.epoll_wait()` as a MQ pump. LDP's `epoll_wait()` calls `vppcom_epoll_wait()` which processes the MQ via `vcl_epoll_wait_handle_mq()`:

```javascript
// Create temporary epoll fd, add target fd, wait for event → MQ drained
var epfd = ldp.epoll_create1(0);
var ev = Memory.alloc(12);
ev.writeU32(0x04); // EPOLLOUT
ev.add(4).writeU32(fd);
ldp.epoll_ctl(epfd, 1 /*EPOLL_CTL_ADD*/, fd, ev);
var events = Memory.alloc(12);
var n = ldp.epoll_wait(epfd, events, 1, 5000); // 5s timeout
ldp.close(epfd);
```

Applied to connect (EPOLLOUT), read (EPOLLIN), and write (EPOLLOUT) hooks.

---

### 5.2 Failed: Pass EINPROGRESS to Go Runtime Poller

**Attempt:** Return EINPROGRESS to Go, letting Go's runtime poller handle async connect via its built-in epoll.

**Why it failed:** Go's runtime poller uses raw `SYSCALL` instructions for `epoll_create1`, `epoll_ctl`, `epoll_pwait` — not libc functions. LDP's `LD_PRELOAD` can't intercept them. Go tried `epoll_ctl(ADD, fd=32)` via raw syscall → kernel EBADF (VCL fake fd). Go fell back to `getsockopt(SO_ERROR)` polling → VPP stub returns 0 forever → infinite getsockopt spam at 100% CPU.

---

### 5.3 IPv4/IPv6 Mismatch — "connect failed! no route"

**Problem:** Go's `net.Listen("tcp", "0.0.0.0:9876")` creates an AF_INET6 socket bound to `[::]:9876`. Client's `net.Dial("tcp", "127.0.0.1:9876")` creates AF_INET. VPP's session lookup doesn't cross-match IPv4 connect against IPv6 listener (unlike Linux kernel which maps via `::ffff:`).

**Fix:** Use `"tcp4"` in both Go binaries to force AF_INET.

---

### 5.4 Goroutine Stack Safety — Spin-Wait vs. Epoll

**Discovery:** Using `ldp.epoll_wait()` in the `accept4` hook caused `SIGSEGV` inside Go's `stackpoolalloc`. The Go scheduler creates small 8KB stacks for goroutines. Frida's `NativeFunction` calls (epoll_create1, epoll_ctl, epoll_wait) consume significant stack space, overflowing the small goroutine stack.

**Fix:** Use spin-wait (no NativeFunction calls) for accept4 and server-side read/write (handleConn goroutines with small stacks). Use epoll-based wait for client goroutines and connect (main goroutine with larger stack).

---

### Session 3 Failed Approaches Summary

| Attempt | Strategy | Why It Failed | Fix |
|---------|----------|---------------|-----|
| Spin-wait read/write on EAGAIN/ENOTCONN | VCL MQ not processed — state never transitions | Use `ldp.epoll_wait()` as MQ pump |
| Pass EINPROGRESS to Go runtime poller | Go's poller uses raw syscalls — can't register VCL fake fds | Handle async connect in Frida hook |
| IPv4 client ↔ IPv6 server | VPP doesn't map IPv4→IPv6 like Linux kernel | Use `"tcp4"` in both binaries |

---

## Part 6: Frida 17 API Compatibility Fixes

During development, Frida 17.9.1 introduced breaking changes from Frida 16:

| Broken API (Frida ≤16) | Replacement (Frida 17) |
|------------------------|------------------------|
| `Module.enumerateSymbols(name, {onMatch, onComplete})` | `Process.getModuleByName(name).enumerateSymbols()` (returns array) |
| `Process.enumerateModules({onMatch, onComplete})` | `Process.enumerateModules()` (returns array) |
| `Module.findExportByName(modName, sym)` static form | `findExport()` helper using `Process.findModuleByName(mod).findExportByName(sym)` |
| `Process.getEnvironmentVariable(name)` | `getenv()` via `NativeFunction` calling libc's `getenv` |
| `--no-pause` CLI flag | Removed in Frida 17 (auto-resume is default) |
| `Module.findExportByName(null, sym)` at spawn time | Must specify module name explicitly (e.g., `'libc.so.6'`) |

**Symptom of callback API:** No symbols found → all hooks silently skipped → binary runs unhooked.  
**Symptom of findExport:** `TypeError: Module.findExportByName is not a function` at load time.

---

## Part 7: Unified Interceptor (interceptor.js)

After `interceptor_server.js` and `interceptor_client.js` were proven working, they were unified into a single `interceptor.js` with these improvements:

1. **Auto-detect Go binary** — scans `Process.enumerateModules()` for Go symbols instead of hardcoding `moduleName`
2. **17 syscalls supported** — added `accept`, `getpeername`, `fcntl`, `epoll_ctl`, `epoll_pwait`, `shutdown`
3. **Auto-resolve VCL library** — searches `VCL_LIB_PATH` env, loaded modules, `LD_LIBRARY_PATH`, system paths
4. **Proper IPv4/IPv6 dual-stack** — `IPV6_V6ONLY` only on IPv6 sockets (not all sockets)
5. **Epoll-based blocking** — `waitForEvent()` helper replaces inline epoll setup
6. **FD tracking with roles** — `_vclFds` tracks family and role (server/client) for stack-safe blocking strategy
7. **Configurable log verbosity** — `LOG_LEVEL` 0/1/2
8. **Pre-cached common errnos** — 19 common errno slots allocated at startup

---

## Appendix: Consolidated Bug Reference

### Design Bugs (Found in Experimental Phase)

| Bug | Root Cause | Fix |
|-----|-----------|-----|
| Go return values corrupted | Only `rax` set; `rbx`/`rcx` left as garbage from C call | Always set `rbx`/`rcx` using `go:itab.syscall.Errno,error` + heap-allocated errno slots |
| Thread-unsafe dispatch | Global flag to identify which syscall is active | Per-invocation state via `this._` in Frida's `onEnter` |
| Assembly shim fragility | prepRegs.asm + two-step replace+attach was brittle | Single `ret` trampoline + JS-side register read/write |

### Runtime Bugs (Found During Debugging Sessions 2 & 3)

| Bug | Symptom | Root Cause | Fix |
|-----|---------|-----------|-----|
| accept4 EBADF | "bad file descriptor" from Go Accept | LDP fake fds (≥32); Go tried epoll on fake fd | Make accept4 blocking (spin-wait EAGAIN) |
| read/write EBADF | Data transfer fails | Kernel read/write return EBADF for VCL fds | Hook `syscall.read`, `write`, `Close` → route through LDP |
| MPTCP duplicate listeners | EADDRINUSE on listen() | Go 1.21+ creates proto=262 socket + regular TCP | Reject proto=262 with EPROTONOSUPPORT |
| IPv6 dual-stack EADDRINUSE | listen() fails | VPP creates IPv4+IPv6 listeners | Set `IPV6_V6ONLY=1` before `ldp.listen()` |
| connect stuck forever | Client hangs | SO_ERROR is VPP stub (returns 0); ldp.poll blocks JS thread | Use `ldp.epoll_wait(EPOLLOUT)` |
| VCL MQ starvation | write ENOTCONN, read EAGAIN forever | `vppcom_session_write/read` don't process MQ | Use `ldp.epoll_wait()` as MQ pump |
| IPv4/IPv6 mismatch | "no route" from VPP | VPP doesn't cross-match IPv4↔IPv6 | Use `"tcp4"` in Go binaries |
| Go runtime poller bypass | EINPROGRESS → getsockopt spam | Go's poller uses raw syscalls for VCL fake fds | Handle async connect entirely in hook |
| goErrFromErrno nil panic | panic: nil pointer dereference | `syscall.Errno` has pointer receivers — data must be `*Errno` | Allocate 8-byte slot per errno |
| findLdpSym returns null | No LDP functions found | Module registered under versioned soname `.so.26.06` | Search modules for 'ldpreload' substring |
| Goroutine stack overflow | SIGSEGV in stackpoolalloc | epoll NativeFunction calls overflow 8KB goroutine stack | Use spin-wait for small-stack goroutines |
