# Analysis of Frida-VPP Interception Attempts

## Background: The Core Problem

The goal is to intercept network syscalls (`socket`, `bind`, `listen`, `accept4`, `connect`, `setsockopt`, `getsockopt`, `getsockname`) in a **Go binary** and redirect them to VPP's VCL library (`libvcl_ldpreload.so`) using Frida.

This is fundamentally difficult because:

1. **Go bypasses libc entirely** — Go's runtime calls the kernel directly via `SYSCALL` instruction through `runtime/internal/syscall.Syscall6`. There are no PLT/GOT entries for `socket`, `bind`, etc. `LD_PRELOAD` has nothing to intercept.
2. **Go uses a different calling convention** (Go ABI) than C libraries (System V AMD64 ABI). Registers carry arguments in different positions.
3. **Go's return convention** differs — syscalls return `(r1, r2, errno)` in `(rax, rbx, rcx)`, not just `rax`.

---

## File-by-File Analysis

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
- Even if they did fire, the `args[0]`, `args[1]`, etc. in Frida's `onEnter` reflect System V ABI register positions (`rdi`, `rsi`, `rdx`), but Go places arguments in `rax`, `rbx`, `rcx` — so arguments would be read as garbage.

**Verdict:** ❌ Completely wrong interception target. Hooks never fire.

---

### `experiments/interceptor3.js` — Replacing Go Symbols with LDP Functions Directly

**Approach:**
- Uses `Module.enumerateSymbols('test_server_go')` to find Go symbols like `syscall.socket`, `syscall.bind`, etc.
- Finds VCL functions from `libvcl_ldpreload.so`.
- Uses `Interceptor.replace(originalSocket, new NativeFunction(vclSocket, 'int', ['int','int','int']))` — directly replacing the Go function entry point with the C VCL function.
- Attaches to both the original and VCL function to log arguments.

**Why It Fails:**
- **ABI mismatch.** When Go calls `syscall.socket(domain, type, protocol)`, the arguments arrive in Go ABI registers:
  - `rax` = domain (e.g., `AF_INET=2`)
  - `rbx` = type (e.g., `SOCK_STREAM=1`)
  - `rcx` = protocol (e.g., `0`)
- But the VCL `socket()` function (System V ABI) reads arguments from:
  - `rdi` = domain
  - `rsi` = type
  - `rdx` = protocol
- Result: VCL reads **garbage** from `rdi/rsi/rdx` (which contain unrelated values), creates the wrong kind of socket, or crashes.
- The `Interceptor.attach()` after `Interceptor.replace()` hooks the **trampoline**, not the original code. `args[0]` etc. read from `rdi/rsi/rdx` which are empty/wrong.

**Verdict:** ❌ Correct interception target, but ABI mismatch causes garbage arguments.

---

### `experiments/interceptor4.js` — Raw Syscall Interception at `syscall.RawSyscall6`

**Approach:**
- Hooks `syscall.RawSyscall6` — the single Go function that funnels **all** syscalls.
- Reads `args[0]` (which Frida maps to `rdi`) as the syscall number.
- Uses a switch statement on the syscall number to identify which syscall is being made.

**Why It Fails:**
- **Wrong register mapping.** `args[0]` in Frida's `onEnter` maps to the `rdi` register (System V convention). But at the entry of `syscall.RawSyscall6`, the Go ABI places:
  - `rax` = syscall number (trap)
  - `rbx` = arg1
  - `rcx` = arg2
  - `rdi` = arg3
  - `rsi` = arg4
  - `r8` = arg5
  - `r9` = arg6
- So `args[0].toInt32()` reads `rdi` which is **arg3** of the syscall, not the syscall number. The switch statement matches random values.
- Even if the syscall number were correctly identified, there's no mechanism to redirect the call to VCL — only logging is attempted.

**Verdict:** ❌ Wrong register indexing. Even correct identification wouldn't solve the redirection problem.

---

### `experiments/interceptor5.js` — The prepRegs Shim Approach (First Attempt)

> **File:** `experiments/interceptor5.js`

**Approach:**
- First file to introduce the `prepRegs.asm` / `libPrepRegs.so` shim concept.
- Loads `libPrepRegs.so` containing `prepRegs` (3-arg) and `prepRegs6` (6-arg) assembly functions that shuffle registers from Go ABI → System V ABI.
- For `socket`: `Interceptor.replace(originalSocket, prepRegsFunction)` → replaces Go's `syscall.socket` with the shim.
- Then `Interceptor.attach(prepRegsFunction, { onLeave })` → after shim runs, calls `ldpSocketFunction(rdi, rsi, rdx)` and does `retval.replace(ret)`.

**Why It Fails:**

1. **Copy-paste bug in `ldpSetSockOptFunction`:**
   ```js
   const ldpSetSockOptFunction = new NativeFunction(ldpSocketAddress, 'int', ['int', 'int', 'int', 'pointer', 'int']);
   //                                                ^^^^^^^^^^^^^^^^ WRONG! Uses socket address, not setsockopt
   ```
   This means `setsockopt` calls actually invoke `socket` with wrong arity.

2. **`prepRegs6Address()` called at end of `onLeave`:**
   ```js
   retval.replace(ret);
   prepRegs6Address(); // This is a NativePointer, not a NativeFunction!
   ```
   Calling a pointer object as a function either crashes or is a no-op.

3. **Go return value convention not handled.** After `retval.replace(fd)`:
   - `rax` = fd (correct)
   - `rbx` = still contains the original `type` argument from before `prepRegs` ran
   - `rcx` = still contains the original `protocol` argument
   - Go interprets `rcx != 0` as a syscall error → Go thinks the call failed.

4. **Multiple `Interceptor.attach` on same trampoline address.** `prepRegsFunction` is used as the replacement for both `socket` and `setsockopt`. Frida attaches to the single `prepRegs` entry point, so `onLeave` can't distinguish which syscall triggered it without additional state.

5. **No `rbx`/`rcx` cleanup.** The `prepRegs` assembly zeros `rax`, `rbx`, `rcx` before `ret`, but after Frida's `onLeave` calls the LDP function and does `retval.replace(ret)`, it only sets `rax`. The Go caller reads `rbx` (second return) and `rcx` (errno) — both are left in undefined states.

**Verdict:** ❌ Right idea, but multiple bugs: copy-paste error, missing return value cleanup, no call disambiguation.

---

### `experiments/interceptor6.js` — The Register Manipulation Graveyard *(deleted)*

> **Status:** This file was deleted during cleanup. It was a massive collection of commented-out,
> overlapping experiments with no single coherent approach. All strategies it attempted are
> documented below for reference.

**Approach:**
A large collection of commented-out experiments trying various strategies:

1. **Calling LDP from `onLeave` after reading `this.context.rdi/rsi/rdx`** (on an attached but non-replaced function).
2. **Manually setting `this.context.rdi = contextInfo.registers[0]` in `onEnter`** before a replaced function runs.
3. **Replacing with LDP then attaching to LDP** to observe what arrives.
4. **Using `Memory.patchCode` with `X86Writer`** to patch the original function at runtime.
5. **Calling LDP from `onEnter`** to intercept before the original runs.

**Why They All Fail:**

| Approach | Problem |
|----------|---------|
| LDP from `onLeave` (attach-only) | By `onLeave`, the real syscall already fired. The kernel already processed `socket()`/`bind()` etc. Calling LDP afterward creates a duplicate. |
| Manual register fix in `onEnter` | Only works if execution is also redirected to LDP. With `attach`-only, execution still goes to Go's syscall path. Setting `rdi/rsi/rdx` has no effect on Go's `rax/rbx/rcx`-based code. |
| Replace with LDP + attach to LDP | ABI mismatch persists — LDP reads `rdi/rsi/rdx` which are not the Go arguments. |
| `Memory.patchCode` | Overwrites the first instruction with `ret`, making the function return immediately. But the return value in `rax` is garbage (whatever was there before). Also corrupts the function permanently. |
| `getContextInfo` helper | The register array indexing is inconsistent: `registers[0]=rax, registers[1]=rbx, registers[2]=rcx, registers[3]=rdi...` but the calling code sometimes uses index 3 for "arg1" and sometimes index 0, causing wrong argument mapping. |

**Verdict:** ❌ Shotgun approach — none of the strategies address the fundamental ABI translation + return value problem.

---

### `experiments/interceptor_full_attempt.js` — The Most Complete Attempt

> **Originally:** `interceptor.js` (root level)

**Approach:**
- Targets `test_server_go` binary.
- Enumerates Go symbols for all socket syscalls.
- Loads both `libvcl_ldpreload.so` and `libPrepRegs.so`.
- Uses `prepRegs2.asm` which provides **separate** `prepRegs`, `prepRegs2`, `prepRegs3`, `prepRegs4`, `prepRegs5` functions (identical code but different symbols) so each syscall can be replaced with its own unique trampoline.
- For each syscall:
  1. `Interceptor.replace(originalXxx, prepRegsN)` — redirect to ABI shim
  2. `Interceptor.attach(originalXxx, ...)` — log entry/exit
  3. `Interceptor.attach(prepRegsN, { onLeave })` — after shim, call corresponding LDP function, `retval.replace(ret)`

**Why It Fails:**

1. **Go return value convention still not handled.** After every LDP call:
   ```js
   retval.replace(ret);  // Sets rax = fd
   // BUT: rbx and rcx are NOT set!
   ```
   Go's caller (`syscall.Socket`, `syscall.Bind`, etc.) reads the return as `(rax, rbx, rcx)`:
   - `rbx` should be `0` (no second return value)  
   - `rcx` should be `0` (no error / errno)
   
   Since `prepRegs` assembly zeros them before returning, **but Frida's `onLeave` runs after that return**, the registers at `onLeave` time have whatever values the NativeFunction LDP call left there. The `retval.replace(ret)` only sets `rax`. `rbx` and `rcx` are corrupted.

2. **accept4 is commented out.** The accept path is the critical server hot-path. Without it:
   ```js
   // Interceptor.replace(originalAccept4, prepRegs6Function); // COMMENTED OUT
   ```
   The server's accept loop still goes to the kernel, not VCL. Even if everything else worked, accept would bypass VCL.

3. **Stack return chain corruption.** `prepRegs` does `ret` to return to Go's `syscall.socket` caller. But the original `syscall.socket` function has a prologue/epilogue that expects certain stack layout. When Frida replaces it with `prepRegs`, the stack frame is different. Go's stack-split check may trigger `"fatal error: runtime: split stack overflow"`.

4. **No error handling for LDP functions.** When LDP returns `-1`, the C errno is in the thread-local `errno` variable, not in a register. The code doesn't translate C errno back into the Go return convention `(rax=-1, rbx=0, rcx=errno_value)`.

**Verdict:** ❌ Closest to correct but fatally flawed by return value corruption and missing rbx/rcx cleanup.

> **See also:** The corrected version is at `interceptor_server.js` (repo root).

---

### `experiments/interceptor_server_v1.js` — Server-Specific Version

> **Originally:** `interceptor_server.js` (root level)

**Approach:**
- Targets `echo_server` binary (instead of `test_server_go`).
- Uses a **global flag** (`isPrepRegsFunctionAttached`) to distinguish which syscall is being intercepted.
- All 3-arg syscalls share a single `prepRegsFunction` trampoline.
- All 6-arg syscalls share a single `prepRegs6Function` trampoline.
- In `prepRegsFunction.onLeave`, checks the flag to decide which LDP function to call.
- Includes `handleError()` that reads C errno via `__errno_location` and sets `rax=-1, rbx=0, rcx=errno`.

**Why It Fails:**

1. **Thread-safety race condition.** `isPrepRegsFunctionAttached` is a **global JS variable**:
   ```js
   let isPrepRegsFunctionAttached = "NULL";
   ```
   Go is massively concurrent — multiple goroutines can call `syscall.socket` and `syscall.bind` simultaneously. Two goroutines calling different syscalls race on this flag:
   - Goroutine A enters `socket` → sets flag to `"socket"`
   - Goroutine B enters `bind` → sets flag to `"bind"`
   - Goroutine A's `prepRegsFunction.onLeave` fires → reads flag as `"bind"` → calls `ldpBindFunction` instead of `ldpSocketFunction`!

2. **Return values still incomplete.** `handleError()` only handles the error case:
   ```js
   function handleError(ret, context, syscallName) {
       if (ret === -1) {
           context.rax = -1;
           context.rbx = 0;
           context.rcx = errno;
       }
   }
   ```
   On **success**, `rbx` and `rcx` are still not set to `0`. Go interprets non-zero `rcx` as an error.

3. **accept4 uses `prepRegs6Function` for a 4-arg call.** `accept4(fd, addr, addrlen, flags)` has 4 arguments in Go ABI. `prepRegs6` maps 6 argument positions, but only 4 are valid — the extra mappings read garbage from `rsi` and `r8`.

**Verdict:** ❌ Thread-unsafe global flag, incomplete return value handling, accept4 arg count mismatch.

> **See also:** The corrected version is at `interceptor_server.js` (repo root).

---

### `experiments/interceptor_client_v1.js` — Client-Specific Version

> **Originally:** `interceptor_client.js` (root level)

**Approach:**
- Targets `echo_client` binary.
- Same architecture as `interceptor_server.js` with global flags.
- Adds `getsockopt` and `connect` interception.
- **accept4 is commented out** (not needed for client).
- Has a `send()/recv()` pause mechanism for debugging.

**Why It Fails:**
- Same **thread-safety** issue with global `isPrepRegsFunctionAttached`.
- Same **incomplete return value** handling (success case doesn't set `rbx=0, rcx=0`).
- `connect` returns `-EINPROGRESS` for non-blocking sockets — this is a common case that needs special handling (Go expects it as an errno, not as a negative return).
- The `send('Pausing execution...')` in `connect`'s `onLeave` blocks the Frida JS thread, halting all interception while waiting for a Python-side resume.

**Verdict:** ❌ Same fundamental issues as server version.

> **See also:** The corrected version is at `interceptor_client.js` (repo root).

---

### `experiments/interceptor_syscall_level.js` — The `syscall.Syscall` / `syscall.RawSyscall6` Approach

> **Originally:** `interceptor2.js` (root level)

**Approach:**
- Targets `echo_server` with a different strategy.
- Attempts to hook at the `syscall.Syscall`, `syscall.Syscall6`, `syscall.RawSyscall6`, and `runtime/internal/syscall.Syscall6` level.
- Uses `Instruction.parse()` to disassemble Go functions and find specific instruction patterns.
- The `executeCodeRange()` function attempts to extract and re-execute specific code ranges from Go functions.

**Why It Fails:**
- `Interceptor.attach(originalSocket, { onEnter })` calls `executeCodeRange(originalSocket)` which tries to disassemble the function. This is a read-only analysis, not an interception mechanism.
- The Stalker-based approach (commented out) would trace all instructions but doesn't redirect execution to VCL.
- The `Interceptor.attach` on `originalRawSyscall6` reads `this.context.rax` as the syscall number — this is correct at `RawSyscall6` entry! But there's no mechanism to prevent the real syscall and redirect to VCL.
- The various Stalker experiments are commented out and incomplete.

**Verdict:** ❌ Mostly diagnostic/exploration code, no actual redirection mechanism.

---

### `experiments/prepRegs.asm` — The Simple ABI Shim

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

**Analysis:**
- Correctly maps 3 Go ABI registers to System V positions.
- Zeros out `rax/rbx/rcx` after the move.
- **Problem:** It only shuffles registers and returns. It doesn't **call** the LDP function. The intent is for Frida's `onLeave` to call the LDP function, but by the time `onLeave` fires, the shim has already returned to the Go caller with garbage in `rax` (zeroed, not the fd).
- Also includes `updateRegs` for error handling and `prepRegs6` for 6-arg calls.

**Verdict:** ⚠️ Correct register mapping, but the two-step approach (shim shuffles, Frida calls LDP in `onLeave`) is fragile and leaves return values in a bad state.

---

### `experiments/prepRegs2.asm` — Multiple Named Shims

- Provides `prepRegs`, `prepRegs2`...`prepRegs5`, `prepRegs6`, `prepRegs7` — identical register-shuffling code under different symbol names.
- This was created to solve the "single trampoline for multiple syscalls" problem — each syscall gets its own named shim so Frida can `attach` to each separately.
- Also includes `prepRegs7` which maps 7 args (treating `rax` as trap number stored in `r10`).
- Includes `checkError` for comparing `rax` with `-1`.

**Verdict:** ⚠️ Correct intent for disambiguation, but still suffers from the same return value problem as `prepRegs.asm`.

---

### `experiments/wrapper.asm` — Assembly Wrapper Attempts

Multiple approaches in one file:

1. **`wrapperFunction`**: Full save/restore of all registers, calls the function pointer in `rax`, handles error checking, and cleans up Go return values. **Problem:** Saves `rax` on stack then `call rax` — but `rax` was already pushed, so `call rax` uses the modified value. Also the stack offset for saving the return value (`[rsp - 8]`) writes below the stack pointer (undefined behavior).

2. **`prepRegs` (Hello World version)**: A debug version that prints "Hello World" via `write` syscall. Used to verify that the assembly shim is being called at all.

3. **`prepRegs` (with function pointer call)**: Takes a function pointer in `rdi`, shuffles Go→SystemV registers, calls the function, and handles the return value. **Problem:** The function pointer was supposed to be the LDP function address, but the `call r12` is commented out — it never actually calls VCL.

**Verdict:** ❌ Experimental/debug code, incomplete implementations.

---

### `experiments/wrapper.go` + `experiments/prepRegs.s` — Go Assembly Approach

**Approach:**
- `wrapper.go` declares `prepRegs(fn uintptr)` as an external function implemented in Go assembly.
- `prepRegs.s` implements the function in Go's plan9 assembly syntax, shuffling registers and calling the function pointer.

**Why It Fails:**
- This would need to be compiled into the target binary at build time — it can't be injected via Frida at runtime.
- The Go assembly approach (`#include "textflag.h"`, `TEXT ·prepRegs(SB)`) is only usable as part of a Go package build.
- The error handling doesn't retrieve C errno (comment says "how do I get it?").

**Verdict:** ❌ Can't be used with Frida runtime injection. Would require modifying the Go binary source.

---

## Summary Table

| File | Target | Strategy | Primary Failure Mode |
|------|--------|----------|---------------------|
| `experiments/interceptor2.js` | libc symbols | Replace libc `socket` etc. | Hooks never fire (Go bypasses libc) |
| `experiments/interceptor3.js` | Go symbols | Direct replace with LDP | ABI mismatch (garbage args) |
| `experiments/interceptor4.js` | `RawSyscall6` | Log-only via attach | Wrong register indexing, no redirect |
| `experiments/interceptor5.js` | Go symbols | prepRegs shim + LDP in onLeave | Copy-paste bug, no return cleanup |
| `experiments/interceptor6.js` *(deleted)* | Go symbols | Various register manipulations | Multiple approaches, all have ABI/timing issues |
| `experiments/interceptor_full_attempt.js` | Go symbols | Per-syscall prepRegs shims | No rbx/rcx cleanup, accept4 missing |
| `experiments/interceptor_server_v1.js` | Go symbols | Shared shim + global flag | Thread-unsafe, incomplete return values |
| `experiments/interceptor_client_v1.js` | Go symbols | Same as server + connect | Thread-unsafe, incomplete return values |
| `experiments/interceptor_syscall_level.js` | Multiple levels | Disassembly/Stalker exploration | No redirection mechanism |
| `experiments/prepRegs.asm` | N/A | 3-arg ABI shim | Doesn't call LDP, return value undefined |
| `experiments/prepRegs2.asm` | N/A | Multiple named shims | Same return value problem |
| `experiments/wrapper.asm` | N/A | Full wrapper attempts | Stack corruption, incomplete |
| `experiments/wrapper.go` | N/A | Go assembly approach | Can't inject via Frida |

---

## The Three Unfixed Bugs Across All Attempts

### Bug 1: Go Return Value Convention
Every attempt sets `rax` with `retval.replace(ret)` but fails to set:
- `rbx = 0` (second return value / no error)
- `rcx = 0` (errno = no error)

Go's caller chain (`syscall.socket` → `syscall.Socket` → `net.sysSocket`) examines all three registers. Stale values in `rbx`/`rcx` cause Go to interpret successful calls as failures.

### Bug 2: Thread Safety
The global `isPrepRegsFunctionAttached` flag races under Go's concurrent goroutine model. Multiple goroutines executing different syscalls simultaneously corrupt each other's dispatch state.

### Bug 3: Blocking Calls in Frida JS
`accept4` is a blocking call. Calling `ldpAccept4Function()` from Frida's `onLeave` handler blocks the Frida JavaScript thread, freezing all other interception. This is why `accept4` is commented out in most files.

---

## Working Solution

The corrected interceptors (`interceptor_server.js` and `interceptor_client.js` at the repo root) fix all three bugs:

1. **Return values:** Always sets `rbx=0, rcx=0` on success, `rbx=0, rcx=errno` on error.
2. **Thread safety:** Uses per-invocation `this._xxx` state instead of global flags.
3. **No assembly shim needed:** Uses `Memory.alloc` + `X86Writer` to create a minimal `ret` trampoline, reads Go ABI registers in `onEnter`, calls LDP in `onLeave`.

See `docs/abi_analysis.md` for the detailed register-level explanation.
