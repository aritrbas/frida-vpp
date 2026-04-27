# Go ABI vs System V AMD64 ABI — Deep Register & Stack Analysis

## Overview

This document provides a detailed analysis of why intercepting Go syscalls and redirecting them to C library functions (VCL/LDP) is fundamentally difficult, based on actual disassembly and GDB stack traces from the target `echo_server` Go binary.

---

## 1. The Two ABIs

### System V AMD64 ABI (Used by C / Linux kernel)

| Purpose | Register |
|---------|----------|
| Arg 1 | `rdi` |
| Arg 2 | `rsi` |
| Arg 3 | `rdx` |
| Arg 4 | `rcx` |
| Arg 5 | `r8` |
| Arg 6 | `r9` |
| Syscall number | `rax` |
| Return value 1 | `rax` |
| Return value 2 | `rdx` |
| Callee-saved | `rbx`, `rbp`, `r12`–`r15` |

### Go ABI (internal, register-based since Go 1.17+)

| Purpose | Register |
|---------|----------|
| Arg 1 (trap/fd) | `rax` |
| Arg 2 | `rbx` |
| Arg 3 | `rcx` |
| Arg 4 | `rdi` |
| Arg 5 | `rsi` |
| Arg 6 | `r8` |
| Arg 7 | `r9` |
| Return value 1 (r1) | `rax` |
| Return value 2 (r2) | `rbx` |
| Return errno | `rcx` |

### The Mapping Conflict

```
Go Arg Position    Go Register    System V Register    System V Arg Position
─────────────────────────────────────────────────────────────────────────────
1st (trap/num)     rax            rdi                  1st
2nd                rbx            rsi                  2nd  
3rd                rcx            rdx                  3rd
4th                rdi            rcx                  4th
5th                rsi            r8                   5th
6th                r8             r9                   6th
```

When Go calls a function with args in `(rax, rbx, rcx)` and Frida replaces it with a C function expecting args in `(rdi, rsi, rdx)`, the C function reads **completely wrong values**.

---

## 2. Go's Syscall Call Chain (From GDB Traces)

### The Full Path for `socket(AF_INET, SOCK_STREAM, 0)`:

```
net.Listen("tcp", ":8080")
  └→ net.(*ListenConfig).Listen
       └→ net.(*sysListener).listenTCP
            └→ net.(*sysListener).listenTCPProto
                 └→ net.internetSocket
                      └→ net.socket                   ← net layer
                           └→ net.sysSocket
                                └→ syscall.Socket      ← syscall wrapper (Go ABI)
                                     └→ syscall.socket  ← lowercase, thin wrapper
                                          └→ syscall.RawSyscall  ← for non-blocking calls
                                               └→ syscall.RawSyscall6  ← Go ABI → stack
                                                    └→ runtime/internal/syscall.Syscall6  ← Go ABI → kernel ABI → SYSCALL
```

### Syscall Numbers (x86_64 Linux):

| Syscall | Number | Go Path | Arg Count |
|---------|--------|---------|-----------|
| `socket` | 41 | `syscall.socket` → `RawSyscall` → `RawSyscall6` | 3 |
| `connect` | 42 | `syscall.connect` → `Syscall` → `RawSyscall6` | 3 |
| `bind` | 49 | `syscall.bind` → `Syscall` → `RawSyscall6` | 3 |
| `listen` | 50 | `syscall.Listen` → `Syscall` → `RawSyscall6` | 2 |
| `getsockname` | 51 | `syscall.getsockname` → `RawSyscall` → `RawSyscall6` | 3 |
| `setsockopt` | 54 | `syscall.setsockopt` → `Syscall6` → `RawSyscall6` | 5 |
| `getsockopt` | 55 | `syscall.getsockopt` → `Syscall6` → `RawSyscall6` | 5 |
| `accept4` | 288 | `syscall.accept4` → `Syscall6` → `RawSyscall6` | 4 |

**Key observation:** Some syscalls go through `syscall.RawSyscall` (no `entersyscall`/`exitsyscall`), others through `syscall.Syscall` (with scheduler notification). This matters for hooking strategy.

---

## 3. Disassembly Analysis

### `runtime/internal/syscall.Syscall6` (The Final Syscall Gate)

```asm
0000000000403f60 <runtime/internal/syscall.Syscall6>:
  403f60:  mov %rsi,%r10        ; Go arg5 (rsi) → kernel arg4 (r10)  [kernel uses r10 instead of rcx]
  403f63:  mov %rdi,%rdx        ; Go arg4 (rdi) → kernel arg3 (rdx)
  403f66:  mov %rcx,%rsi        ; Go arg3 (rcx) → kernel arg2 (rsi)
  403f69:  mov %rbx,%rdi        ; Go arg2 (rbx) → kernel arg1 (rdi)
  403f6c:  syscall              ; rax = syscall number (already in place from Go arg1)
  403f6e:  cmp $0xfffffffffffff001,%rax   ; Check for error (rax > -4095)
  403f74:  jbe 403f8b           ; Jump if success
  ; ERROR PATH:
  403f76:  neg %rax             ; rax = -rax (positive errno)
  403f79:  mov %rax,%rcx        ; rcx = errno (Go return convention)
  403f7c:  mov $0xffffffffffffffff,%rax   ; rax = -1 (error indicator)
  403f83:  mov $0x0,%rbx        ; rbx = 0 (second return value)
  403f8a:  ret
  ; SUCCESS PATH:
  403f8b:  mov %rdx,%rbx        ; rbx = rdx (second return value from kernel)
  403f8e:  mov $0x0,%rcx        ; rcx = 0 (no error)
  403f95:  ret
```

**This is the critical code.** It shows exactly how Go maps arguments:

```
BEFORE syscall instruction:
  rax = syscall number (from Go arg1, e.g., 41 for socket)
  rdi = Go arg2 (e.g., domain = AF_INET = 2)
  rsi = Go arg3 (e.g., type = SOCK_STREAM | SOCK_CLOEXEC)
  rdx = Go arg4 (e.g., protocol = 0)
  r10 = Go arg5
  r8  = Go arg6 (already in correct position)
  r9  = Go arg7 (already in correct position)

AFTER syscall returns:
  SUCCESS: rax = result, rbx = rdx (second retval), rcx = 0
  ERROR:   rax = -1, rbx = 0, rcx = positive errno
```

### `syscall.Syscall` (3-arg wrapper with scheduler notification)

```asm
00000000004848c0 <syscall.Syscall>:
  ; PROLOGUE — save to stack (Go calling convention)
  4848c0:  push %rbp
  4848c1:  mov %rsp,%rbp
  4848c4:  sub $0x50,%rsp
  4848c8:  mov %rax,0x60(%rsp)   ; Save trap number
  4848cd:  mov %rbx,0x68(%rsp)   ; Save arg1
  4848d2:  mov %rcx,0x70(%rsp)   ; Save arg2
  4848d7:  mov %rdi,0x78(%rsp)   ; Save arg3
  
  ; ENTER SYSCALL — notify Go scheduler
  4848e0:  call runtime.entersyscall
  
  ; RESTORE args from stack (entersyscall may clobber registers)
  4848e5:  mov 0x60(%rsp),%rax   ; Restore trap number
  4848ea:  mov 0x68(%rsp),%rbx   ; Restore arg1
  4848ef:  mov 0x70(%rsp),%rcx   ; Restore arg2
  4848f4:  mov 0x78(%rsp),%rdi   ; Restore arg3
  
  ; ZERO unused args (only 3 args for Syscall)
  4848f9:  xor %esi,%esi         ; arg4 = 0
  4848fb:  mov %rsi,%r8          ; arg5 = 0
  4848fe:  mov %rsi,%r9          ; arg6 = 0
  
  ; CALL RawSyscall6
  484901:  call syscall.RawSyscall6
  
  ; SAVE return values to stack
  484906:  mov %rax,0x48(%rsp)   ; r1
  48490b:  mov %rbx,0x40(%rsp)   ; r2
  484910:  mov %rcx,0x38(%rsp)   ; errno
  
  ; EXIT SYSCALL — notify Go scheduler
  484915:  call runtime.exitsyscall
  
  ; RESTORE return values from stack
  48491a:  mov 0x48(%rsp),%rax   ; r1
  48491f:  mov 0x40(%rsp),%rbx   ; r2
  484924:  mov 0x38(%rsp),%rcx   ; errno
  
  ; EPILOGUE
  484929:  add $0x50,%rsp
  48492d:  pop %rbp
```

**Key insight:** `syscall.Syscall` saves ALL register args to the stack, calls `entersyscall`, restores them, calls `RawSyscall6`, saves results, calls `exitsyscall`, restores results, and returns. The return values `(rax, rbx, rcx)` propagate ALL the way back up the chain.

### `syscall.Syscall6` (6-arg wrapper)

```asm
0000000000484940 <syscall.Syscall6>:
  ; Same pattern as Syscall but saves 7 registers:
  484948:  mov %rax,0x60(%rsp)   ; trap
  48494d:  mov %rbx,0x68(%rsp)   ; arg1
  484952:  mov %rcx,0x70(%rsp)   ; arg2
  484957:  mov %rdi,0x78(%rsp)   ; arg3
  48495c:  mov %rsi,0x80(%rsp)   ; arg4
  484964:  mov %r8,0x88(%rsp)    ; arg5
  48496c:  mov %r9,0x90(%rsp)    ; arg6
  ; ... entersyscall, restore, call RawSyscall6, save, exitsyscall, restore, ret
```

---

## 4. Register State at Each Interception Point

### At `syscall.socket` entry (where Frida hooks):

For `socket(AF_INET=2, SOCK_STREAM|SOCK_CLOEXEC=0x80801, 0)`:

```
Register   Value          Meaning in Go ABI
────────────────────────────────────────────
rax        2              domain (AF_INET)           ← Go arg1
rbx        0x80801        type (SOCK_STREAM|flags)   ← Go arg2
rcx        0              protocol                   ← Go arg3
rdi        (garbage)      not used
rsi        (garbage)      not used
rdx        (garbage)      not used
```

### After `prepRegs` shim runs:

```
Register   Value          Meaning
────────────────────────────────────
rdi        2              domain    ← Now in System V arg1 position ✓
rsi        0x80801        type      ← Now in System V arg2 position ✓
rdx        0              protocol  ← Now in System V arg3 position ✓
rax        0              zeroed
rbx        0              zeroed
rcx        0              zeroed
```

### After LDP `socket()` call (in Frida's `onLeave`):

```
Register   Value          Meaning
────────────────────────────────────
rax        3              fd returned by VCL        ← Set by retval.replace(3)
rbx        ????????       UNKNOWN — clobbered by C call!  ← NOT SET
rcx        ????????       UNKNOWN — clobbered by C call!  ← NOT SET
```

### What Go expects when `syscall.socket` returns:

```
Register   Expected       Meaning
────────────────────────────────────
rax        3              fd (success)
rbx        0              second return value (unused, must be 0)
rcx        0              errno (0 = no error)
```

**THE BUG: `rbx` and `rcx` are not set to 0 after the LDP call, so Go interprets them as error indicators.**

---

## 5. Tracing the Return Value Propagation

Using `socket` as the example, here's how return values propagate back:

```
runtime/internal/syscall.Syscall6:
    syscall → rax=3, rbx=rdx, rcx=0         ; Kernel returns fd=3
    return (rax=3, rbx=0, rcx=0)             ; Success: rbx=rdx(0), rcx=0

syscall.RawSyscall6:
    pass-through of (rax, rbx, rcx)          ; rax=3, rbx=0, rcx=0

syscall.RawSyscall / syscall.Syscall:
    save rax→stack, rbx→stack, rcx→stack     ; Save (3, 0, 0)
    call runtime.exitsyscall
    restore rax←stack, rbx←stack, rcx←stack  ; Restore (3, 0, 0)
    return (rax=3, rbx=0, rcx=0)

syscall.socket(domain, typ, proto) (fd int, err error):
    r1, r2, errno := RawSyscall(SYS_SOCKET, domain, typ, proto)
    if errno != 0 { return -1, errno }       ; ← CHECKS rcx (errno)
    return int(r1), nil                       ; ← Returns rax as fd

syscall.Socket:
    fd, err := socket(domain, typ, proto)
    if err != nil { return -1, err }          ; ← If rcx was non-zero, this fires
    return fd, nil
```

**If `rcx` is non-zero when `syscall.socket` returns, Go treats it as errno, wraps it in an error, and the socket creation "fails" — even if VCL actually succeeded and returned a valid fd in `rax`.**

---

## 6. The `setsockopt` / `accept4` 6-Argument Complexity

### `setsockopt(fd=3, SOL_SOCKET=1, SO_REUSEADDR=2, &val, sizeof(int)=4)`:

At `syscall.setsockopt` entry (Go ABI):
```
rax = fd (3)           → needs to go to rdi
rbx = level (1)        → needs to go to rsi
rcx = optname (2)      → needs to go to rdx
rdi = optval (ptr)     → needs to go to rcx
rsi = optlen (4)       → needs to go to r8
```

The `prepRegs6` shim must handle the additional complexity of saving and shuffling `rdi`, `rsi`, and `r8`:

```nasm
prepRegs6:
    push r12                  ; Save callee-saved register
    mov r10, rdi              ; Save original rdi (Go arg4)
    mov r11, rsi              ; Save original rsi (Go arg5)
    mov r12, r8               ; Save original r8 (Go arg6)
    mov rdi, rax              ; Go arg1 → SysV arg1
    mov rsi, rbx              ; Go arg2 → SysV arg2
    mov rdx, rcx              ; Go arg3 → SysV arg3
    mov rcx, r10              ; Go arg4 → SysV arg4
    mov r8, r11               ; Go arg5 → SysV arg5
    mov r9, r12               ; Go arg6 → SysV arg6
    xor rax, rax
    xor rbx, rbx
    pop r12
    ret
```

**Problem with `accept4`:** Go calls `syscall.accept4(fd, rsa, addrlen, flags)` — 4 args. But `prepRegs6` maps 6 register positions. Args 5 and 6 (`rsi` and `r8` in Go ABI) contain garbage from the caller's frame, and `prepRegs6` dutifully maps them to `r8` and `r9` in System V ABI. The LDP `accept4()` function may read these garbage values.

### `accept4` blocking behavior:

```
internal/poll.(*FD).Accept
  → internal/poll.accept(s)
    → syscall.Accept4(fd, flags)
      → syscall.accept4(s, rsa, addrlen, flags)
        → syscall.Syscall6(SYS_ACCEPT4, fd, addr, addrlen, flags, 0, 0)
```

`accept4` is called in a loop. When called through VCL, `vppcom_session_accept()` blocks until a client connects. Calling this from Frida's JavaScript `onLeave` handler blocks the **entire Frida JS event loop**, preventing any other hooks from executing.

---

## 7. The `connect` Special Case

`connect` on a non-blocking socket returns `-EINPROGRESS` (errno 115):

```
At kernel level:
    rax = -115  (which is > -4096, so treated as error)

In Syscall6 error path:
    neg rax → 115
    mov rcx, rax → rcx = 115
    mov rax, -1
    mov rbx, 0
    
Go receives: rax=-1, rbx=0, rcx=115 (EINPROGRESS)
```

The VCL `connect()` function also returns `-1` with `errno=EINPROGRESS` for async connects. The C errno is stored in thread-local storage (`__errno_location()`), not in a register. The interceptor must:

1. Call `ldpConnectFunction()`
2. If return is `-1`, read errno via `errnoFuncC().readInt()`
3. Set `rax=-1`, `rbx=0`, `rcx=errno_value`

The `handleError` function in `experiments/interceptor_server_v1.js` attempts this but only handles the error case, not the success case.

---

## 8. Why `Interceptor.replace` + `Interceptor.attach` Interaction Matters

When you do:
```js
Interceptor.replace(originalSocket, prepRegsFunction);
Interceptor.attach(originalSocket, { onEnter, onLeave });
```

Frida does:
1. At `originalSocket` address, install a **trampoline** that jumps to `prepRegsFunction`.
2. The `attach` hooks the **trampoline entry and exit**, not the original code.

Timeline:
```
1. Go calls syscall.socket → hits trampoline at originalSocket address
2. onEnter fires (context has Go ABI registers: rax=domain, rbx=type, rcx=proto)
3. Trampoline jumps to prepRegsFunction
4. prepRegs shuffles registers (rdi=domain, rsi=type, rdx=proto)
5. prepRegs executes `ret` → returns to trampoline
6. onLeave fires (context now has: rdi=domain, rsi=type, rdx=proto, rax=0, rbx=0, rcx=0)
7. In onLeave: call ldpSocket(rdi, rsi, rdx) → returns fd
8. retval.replace(fd) → sets rax=fd
9. Trampoline returns to Go caller
10. Go reads (rax=fd, rbx=???, rcx=???) ← rbx and rcx are whatever the LDP call left behind
```

**The fix must set `this.context.rbx = 0` and `this.context.rcx = 0` in `onLeave` after every successful LDP call.**

---

## 9. Required Register State for Correct Return

### On Success:

```js
onLeave: function(retval) {
    var ret = ldpFunction(...);
    if (ret >= 0) {
        retval.replace(ret);
        this.context.rbx = 0;   // second return value = 0
        this.context.rcx = 0;   // errno = 0 (no error)
    } else {
        var errno = errnoFuncC().readInt();
        retval.replace(-1);
        this.context.rbx = 0;   // second return value = 0
        this.context.rcx = errno; // errno from C
    }
}
```

### The Complete Register Translation Table:

For `socket(domain=2, type=1, proto=0)`:

```
Stage              rax    rbx     rcx     rdi    rsi    rdx    r8    r9
───────────────────────────────────────────────────────────────────────
Go entry           2      1       0       ?      ?      ?      ?     ?
After prepRegs     0      0       0       2      1      0      ?     ?
After LDP call     3      ?       ?       ?      ?      ?      ?     ?
Required return    3      0       0       ?      ?      ?      ?     ?
                   ↑fd    ↑no-r2  ↑no-err
```

For `setsockopt(fd=3, SOL_SOCKET=1, SO_REUSEADDR=2, &val, 4)`:

```
Stage              rax    rbx     rcx     rdi    rsi    rdx    rcx   r8    r9
──────────────────────────────────────────────────────────────────────────────
Go entry           3      1       2       &val   4      ?      -     ?     ?
After prepRegs6    0      0       ?       3      1      2      &val  4     ?
After LDP call     0      ?       ?       ?      ?      ?      ?     ?     ?
Required return    0      0       0       ?      ?      ?      ?     ?     ?
                   ↑ok    ↑no-r2  ↑no-err
```

---

## 10. Summary of Root Causes

| Root Cause | Impact | Which Files Affected |
|------------|--------|---------------------|
| Go bypasses libc (direct SYSCALL) | LD_PRELOAD / libc hooks never fire | `experiments/interceptor2.js` |
| Go ABI args in `rax,rbx,rcx` vs System V `rdi,rsi,rdx` | C functions receive garbage arguments | `experiments/interceptor3.js`, all replace-with-LDP attempts |
| Go returns `(rax, rbx, rcx)` not just `rax` | Go misinterprets successful calls as errors | ALL experiment interceptor files |
| Global mutable state for call dispatch | Race conditions under concurrent goroutines | `experiments/interceptor_server_v1.js`, `experiments/interceptor_client_v1.js` |
| Blocking `accept4` in Frida JS thread | Frida event loop freezes | `experiments/interceptor_v1.js`, `experiments/interceptor_server_v1.js` |
| `prepRegs` only shuffles, doesn't call LDP | Two-step approach leaves return value undefined | All prepRegs-based approaches |

---

## 11. Frida 17 API Changes and Their Impact

Frida 17 introduced several breaking API changes that affected the working interceptors. Understanding these is necessary to maintain compatibility.

### Enumerate APIs Now Return Arrays

The callback-based `{onMatch, onComplete}` style is gone. Old scripts that called:
```js
Module.enumerateSymbols('echo_server', { onMatch: fn, onComplete: fn });
```
silently found zero symbols — no error, just no results. The fix:
```js
Process.getModuleByName('echo_server').enumerateSymbols().forEach(function(sym) { ... });
```

### `Module.findExportByName()` Static Form Removed

Old code `Module.findExportByName('libc.so.6', 'getenv')` now throws `TypeError`. The working interceptors use a `findExport()` helper:
```js
function findExport(modName, symName) {
    var mod = Process.findModuleByName(modName);
    if (!mod) {
        var addr = null;
        Process.enumerateModules().some(function(m) {
            var a = m.findExportByName(symName);
            if (a) { addr = a; return true; }
            return false;
        });
        return addr;
    }
    return mod.findExportByName(symName);
}
```

### `Process.getEnvironmentVariable()` Removed

This function does not exist in Frida 17. The working interceptors read environment variables via libc's `getenv`:
```js
var _getenv = new NativeFunction(
    findExport('libc.so.6', 'getenv'), 'pointer', ['pointer']
);
function getEnv(name) {
    var p = _getenv(Memory.allocUtf8String(name));
    return p.isNull() ? null : p.readUtf8String();
}
```

### Correct Go Error Interface Return (Updated — Session 2)

The earlier understanding "set `rcx = errno_int`" was wrong for the Go error interface. The `syscall` package's higher-level functions (`syscall.socket`, `syscall.bind`, etc.) return Go `error` interface values, not raw integers. The interface has two pointer fields: `itab` and `data`.

**Session 2 correction:** The pre-cached `syscall.errEAGAIN/errEINVAL/errENOENT` objects only cover three errno values. For arbitrary errno values, use `go:itab.syscall.Errno,error`:

```js
// go:itab.syscall.Errno,error is the interface table for syscall.Errno as error
var goErrnoItab = goErrSyms['go:itab.syscall.Errno,error'];

// CRITICAL: syscall.Errno methods use POINTER receivers.
// Therefore: interface.data must be a POINTER to the errno value, not inline.
function goErrFromErrno(errno) {
    if (!_errnoDataCache[errno]) {
        var slot = Memory.alloc(8);   // persistent 8-byte allocation
        slot.writeU64(errno);          // write errno value into slot
        _errnoDataCache[errno] = slot;
    }
    return { itab: goErrnoItab, data: _errnoDataCache[errno] };
    //                                      ↑ pointer to errno, not errno itself
}
```

**Why pointer is required:**
```go
// Go source: syscall/types_linux.go
type Errno uintptr

// Error method has POINTER receiver:
func (e *Errno) Error() string {
    // *e is the errno value (dereferences the pointer)
    if 0 <= int(*e) && int(*e) < len(errorTable) { ... }
}
```

When Go calls `err.Error()`, it dereferences the data pointer as `*Errno`. If data=9 (inline integer, not a pointer), it tries to dereference address 0x9 → segfault.

### `--no-pause` Flag Removed

Frida 17 auto-resumes the target by default. All run commands should omit `--no-pause`:
```bash
# Frida 17+
frida -f ./test/echo_server -l interceptor.js
```

---

## 12. Session 2 Discoveries — VCL Fake FD Architecture

### 12.1 LDP Fake File Descriptor Numbers

VPP's LDP does not use real kernel file descriptors for VCL sessions. Instead, it maintains a mapping:

```
VCL session handle (vlsh) → fake fd = vlsh + vlsh_bit_val

Default vlsh_bit_val = (1 << LDP_SID_BIT_MIN) = (1 << 5) = 32
```

So the first VCL socket returns fd=32, the second returns fd=33, etc.

**Impact on interception:**
- `ldp.socket()` returns 32, not 3 or 4 like kernel sockets
- `ldp.accept4()` returns 33, 34, etc. for connected sessions
- These fd numbers exist ONLY in LDP's internal table — the kernel knows nothing about them
- Any Go code that calls the kernel with fd=32 gets EBADF

**The complete set of syscalls that must be hooked:**

| Syscall | Why hook it |
|---------|-------------|
| `socket` | Gets initial VCL fd (=32) |
| `bind` | Routes through LDP using VCL fd |
| `listen` | Routes through LDP |
| `accept4` | Returns new VCL fd (=33+) for each connection |
| `connect` | Routes through LDP |
| `setsockopt` / `getsockopt` / `getsockname` | Routes through LDP |
| **`read`** | **VCL fd≥32 → kernel EBADF without this hook** |
| **`write`** | **VCL fd≥32 → kernel EBADF without this hook** |
| **`close`** | **VCL fd≥32 → kernel EBADF without this hook** |

### 12.2 LDP FD Dispatch Logic

```c
// LDP routes based on fd value:
static vls_handle_t ldp_fd_to_vlsh(int fd) {
    if (fd < ldp->vlsh_bit_val) {
        return VLS_INVALID_HANDLE;  // → libc kernel path
    }
    return (fd - ldp->vlsh_bit_val);  // → VCL session path
}
```

In practice:
- `ldp.read(fd=5, ...)` → `fd < 32` → `libc_read(5, ...)` (kernel passthrough)
- `ldp.read(fd=32, ...)` → `fd ≥ 32` → `vls_read(vlsh=0, ...)` (VCL path)
- `ldp.read(fd=33, ...)` → `fd ≥ 32` → `vls_read(vlsh=1, ...)` (VCL path)

### 12.3 VPPCOM_ATTR_GET_ERROR Stub

`getsockopt(SO_ERROR)` on a VCL fd always returns 0, regardless of actual session state:

```c
// vppcom.c
case VPPCOM_ATTR_GET_ERROR:
    if (buffer && buflen && (*buflen >= sizeof (int))) {
        *(int *) buffer = 0;   // ← ALWAYS ZERO, unconditionally
        *buflen = sizeof (int);
        VDBG (2, "VPPCOM_ATTR_GET_ERROR: %d, buflen %d, #VPP-TBD#", ...);
        //                                                  ↑ marked as TODO
    }
```

This makes the standard POSIX pattern for non-blocking connect detection impossible:
```js
// DOES NOT WORK with VCL:
while (getsockopt(SO_ERROR) === EINPROGRESS) { poll/sleep; }
```

### 12.4 VCL Session States for connect

```
vppcom_session_connect() with VCL_SESS_ATTR_NONBLOCK set:
    → Sends connect request to VPP
    → Sets session state to VCL_STATE_UPDATED
    → Returns VPPCOM_EINPROGRESS immediately

Session state transitions:
    VCL_STATE_UPDATED (connecting)
    → [VPP processes SYN, responds]
    → VCL_STATE_READY (connected)

vcl_session_write_ready() returns:
    VCL_STATE_READY:   → svm_fifo_max_enqueue_prod() > 0 (positive)
    VCL_STATE_UPDATED: → 0 (not writable yet)
    Other states:      → VPPCOM_ENOTCONN (negative)
```

**Consequence:** `ldp.poll(POLLOUT)` works correctly — when session transitions to `VCL_STATE_READY`, poll returns POLLOUT. BUT calling `ldp.poll` from Frida's JS thread freezes the entire Frida event loop (see section 12.5).

### 12.5 Blocking LDP Calls from Frida JS Thread

**Critical constraint:** The Frida JS engine runs on a single thread. All `onEnter`/`onLeave` hooks share this thread. If any hook calls a blocking function (accept4, read, poll), ALL other hooks are frozen until it returns.

```
Frida JS thread timeline:

    hookSocket.onLeave  ── fast (ldp.socket returns immediately)  ──→ done
    hookBind.onLeave    ── fast ──────────────────────────────────→ done
    hookListen.onLeave  ── fast ──────────────────────────────────→ done
    hookAccept4.onLeave ── BLOCKS (waiting for client connection) ─→ ...
                           [While blocked: no other hooks can fire]
                           [No getsockname, setsockopt, etc.]
    hookRead.onLeave    ── BLOCKS on EAGAIN retry ─────────────────→ ...
```

**Mitigations used:**
- **accept4:** Blocking is acceptable here — Go only calls accept4 once per connection, and the spin-wait with 1ms sleep is functionally equivalent to a blocking accept.
- **read (server):** Spin-wait with 1ms sleep on EAGAIN. Acceptable because VCL data delivery is fast once the session is established.
- **read (client — Session 3 fix):** `ldp.epoll_wait(EPOLLIN, 5s)` to drain the VCL MQ and wait for data. See Section 12.9.
- **write (client — Session 3 fix):** `ldp.epoll_wait(EPOLLOUT, 5s)` on EAGAIN/ENOTCONN for VCL fds.
- **connect (EINPROGRESS — Session 3 fix):** `ldp.epoll_wait(EPOLLOUT, 5s)` to wait for session READY. Do NOT call ldp.poll (blocks indefinitely). Do NOT return EINPROGRESS to Go (Go's runtime poller uses raw syscalls that bypass LDP). See Section 12.9.

### 12.6 Go MPTCP Support (Go 1.21+)

Go 1.21+ added MPTCP support. When `net.Listen("tcp", ...)` is called, Go also tries:
```
socket(AF_INET6, SOCK_STREAM, IPPROTO_MPTCP=262)
```
in addition to the regular TCP socket. Both attempts are non-fatal: if MPTCP socket fails, Go falls back.

**VPP impact:** LDP receives both socket calls. VPP doesn't support MPTCP over VCL. The MPTCP socket creates a VCL session (proto=TCP internally), and both sessions compete to bind/listen on port 9876 → second listen fails with EADDRINUSE.

**Fix:** In socket `onLeave`, detect proto=262 and return EPROTONOSUPPORT. Go's MPTCP fallback handles this gracefully.

### 12.7 IPv6 Dual-Stack and VPP

Go's `net.Listen("tcp", ":9876")` uses `[::]:9876` (IPv6 address). By default, Linux IPv6 sockets have dual-stack enabled (IPV6_V6ONLY=0), meaning the socket also accepts IPv4 connections.

**VPP behavior:** When VCL receives a bind on `[::]`, with dual-stack enabled it attempts to create both an IPv6 AND an IPv4 listener on the same port. The second `vppcom_session_listen()` call fails with VPPCOM_EADDRINUSE.

**Fix:** Before calling `ldp.listen()`, set `IPV6_V6ONLY=1`:
```js
ldp.setsockopt(this._fd, 41 /*IPPROTO_IPV6*/, 26 /*IPV6_V6ONLY*/, v6onlyBuf, 4);
ldp.listen(this._fd, this._backlog);
```

### 12.8 Go Binary Symbol Addresses (echo_server, Go 1.24.4 linux/amd64)

```
Symbol                        Address     Args (Go ABI)
──────────────────────────────────────────────────────────────────────────
syscall.socket                0x48ff40    rax=domain, rbx=type, rcx=proto
syscall.bind                  0x48fc00    rax=fd, rbx=addr_ptr, rcx=addrlen
syscall.Listen                0x48f960    rax=fd, rbx=backlog
syscall.accept4               0x48fb00    rax=fd, rbx=addr_ptr, rcx=addrlen_ptr, rdi=flags
syscall.connect               0x48fce0    rax=fd, rbx=addr_ptr, rcx=addrlen
syscall.getsockname           0x490100    rax=fd, rbx=addr_ptr, rcx=addrlen_ptr
syscall.getsockopt            0x4907c0    rax=fd, rbx=level, rcx=optname, rdi=optval_ptr, rsi=optlen_ptr
syscall.setsockopt            0x4908c0    rax=fd, rbx=level, rcx=optname, rdi=optval_ptr, rsi=optlen
syscall.read                  0x48f520    rax=fd, rbx=buf_ptr, rcx=buf_len
syscall.write                 0x48f6e0    rax=fd, rbx=buf_ptr, rcx=buf_len
syscall.Close                 0x48f280    rax=fd
go:itab.syscall.Errno,error   0x5489d8    (itab pointer for error interface)
```

Note: `syscall.read` and `syscall.write` take `[]byte` slice as arg2/arg3:
- Go slice layout: `{ptr, len, cap}` in consecutive argument registers
- For `read(fd, p []byte)`: rax=fd, rbx=p.ptr, rcx=p.len, rdi=p.cap
- We only need ptr and len for the C call; cap is ignored

---

## 13. Session 3 Discoveries — VCL Message Queue and epoll_wait

### 13.1 VCL Message Queue (MQ) Starvation

**Critical discovery:** `vppcom_session_write()` and `vppcom_session_read()` do NOT process the VCL worker's message queue (MQ). When VPP completes an async operation (e.g., TCP handshake), it places the result (e.g., `SESSION_CONNECTED`) in the worker's MQ. If no MQ-draining function is called, the event stays unread and the session state never transitions.

**Functions that DO process the MQ:**
- `vppcom_epoll_wait()` → calls `vcl_epoll_wait_handle_mq()`
- `vppcom_select()` → processes MQ internally

**Functions that do NOT process the MQ:**
- `vppcom_session_read()` — only checks `session->session_state`
- `vppcom_session_write()` — only checks `vcl_session_write_ready()`

**Consequence for Frida hooks:** Spin-waiting on `ldp.read()` or `ldp.write()` EAGAIN/ENOTCONN retries never makes progress because the session state transition event is stuck in the MQ. The session remains in `VCL_STATE_UPDATED` forever.

### 13.2 LDP epoll_wait as MQ Pump Pattern

The fix for all blocking VCL I/O from Frida hooks is to use `ldp.epoll_wait()` which routes through `vppcom_epoll_wait()` and processes the MQ:

```javascript
// Generic pattern:
function waitForVclEvent(fd, epollEvents, timeoutMs) {
    var epfd = ldp.epoll_create1(0);
    if (epfd < 0) return -1;
    var ev = Memory.alloc(12);
    ev.writeU32(epollEvents);  // EPOLLIN=0x01, EPOLLOUT=0x04
    ev.add(4).writeU32(fd);
    ldp.epoll_ctl(epfd, 1 /*ADD*/, fd, ev);
    var events = Memory.alloc(12);
    var n = ldp.epoll_wait(epfd, events, 1, timeoutMs);
    ldp.close(epfd);
    return n;  // >0 = event fired, 0 = timeout, <0 = error
}

// Usage:
// connect: waitForVclEvent(fd, 0x04 /*EPOLLOUT*/, 5000)
// read:    waitForVclEvent(fd, 0x01 /*EPOLLIN*/,  5000)
// write:   waitForVclEvent(fd, 0x04 /*EPOLLOUT*/, 5000)
```

**Why this works and ldp.poll() doesn't:**
- `ldp.epoll_wait()` is implemented as a busy-poll internally with short timeouts, checking the MQ between iterations
- `ldp.poll()` also works in principle but blocks the Frida JS thread completely (no yield)
- Both process the MQ, but `epoll_wait` with a bounded timeout is safer from Frida's event loop perspective

### 13.3 Go Runtime Poller Bypasses LDP (Cannot Delegate Async I/O to Go)

Go's runtime poller (`runtime/netpoll_epoll.go`) uses raw `SYSCALL` instructions for `epoll_create1`, `epoll_ctl`, and `epoll_pwait`. These bypass LDP's `LD_PRELOAD` interception entirely.

```
Go runtime poller:
  epoll_create1() → raw syscall → kernel epoll fd
  epoll_ctl(ADD, fd=32) → raw syscall → kernel: fd=32 doesn't exist → EBADF
```

This means:
- Cannot pass EINPROGRESS to Go — the runtime poller can't register VCL fake fds
- Cannot use Go's built-in non-blocking I/O for VCL sessions
- All async waiting must be done in the Frida JS hooks via `ldp.epoll_*`
- This is why `accept4` must be made blocking in the hook (Go's poller path doesn't work for VCL fds)

### 13.4 IPv4/IPv6 Mismatch in VPP Session Lookup

VPP's session lookup does not match IPv4 connect requests against IPv6 listeners:

```
Server: socket(AF_INET6) → bind([::]:9876) → listen()
  → VPP creates transport endpoint: [::]:9876 (IPv6)

Client: socket(AF_INET) → connect(127.0.0.1:9876)
  → VPP looks for: 127.0.0.1:9876 (IPv4)
  → No match! → "connect failed! no route"
```

Go's `net.Listen("tcp", "0.0.0.0:9876")` creates an AF_INET6 socket (even with an IPv4 address!) because Go prefers dual-stack. The fix is to use `"tcp4"` to force AF_INET in both server and client.

Unlike the Linux kernel (which maps IPv4 connections to `[::]` listeners via `::ffff:127.0.0.1`), VPP treats IPv4 and IPv6 as separate transport spaces with no mapping between them.
