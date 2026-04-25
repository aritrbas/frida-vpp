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
| Blocking `accept4` in Frida JS thread | Frida event loop freezes | `experiments/interceptor_full_attempt.js`, `experiments/interceptor_server_v1.js` |
| `prepRegs` only shuffles, doesn't call LDP | Two-step approach leaves return value undefined | All prepRegs-based approaches |
