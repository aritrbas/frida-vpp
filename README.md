# frida-vpp — Frida-Based VCL Interception for Go Binaries

## Problem

[VPP](https://fd.io/)'s VCL (VPP Communications Library) provides a user-space networking stack via `libvcl_ldpreload.so`, which intercepts POSIX socket calls through `LD_PRELOAD`. This works transparently for **C programs** because they call socket functions through libc's PLT/GOT.

**Go programs bypass libc entirely.** The Go runtime issues syscalls directly via the `SYSCALL` instruction (`runtime/internal/syscall.Syscall6`), so `LD_PRELOAD` has nothing to intercept. Additionally, Go uses its own register-based calling convention (Go ABI) that differs from the System V AMD64 ABI used by C libraries:

| Arg | Go ABI Register | System V Register |
|-----|----------------|-------------------|
| 1st | `rax` | `rdi` |
| 2nd | `rbx` | `rsi` |
| 3rd | `rcx` | `rdx` |
| Return | `rax, rbx, rcx` | `rax, rdx` |

This project uses [Frida](https://frida.re/) to dynamically intercept Go's socket-layer syscalls at runtime and redirect them to VCL, bridging the ABI gap.

## Repository Structure

```
frida-vpp/
├── interceptor_server.js          # Working Frida script for Go server binaries
├── interceptor_client.js          # Working Frida script for Go client binaries
├── docs/
│   ├── failed_attempt_analysis.md # Detailed analysis of each experimental approach and why it failed
│   └── abi_analysis.md            # Deep dive into Go ABI vs System V ABI register mapping
├── test/
│   ├── echo_server.go             # Sample TCP echo server for testing
│   ├── echo_client.go             # Sample TCP echo client for testing
│   └── README.md                  # Build, run, and test instructions
└── experiments/                   # All previous experimental attempts (for reference)
    ├── interceptor2.js            # Attempt: Hook libc symbols (fails — Go bypasses libc)
    ├── interceptor3.js            # Attempt: Direct replace Go symbols with LDP (fails — ABI mismatch)
    ├── interceptor4.js            # Attempt: Hook RawSyscall6 (fails — wrong register indexing)
    ├── interceptor5.js            # Attempt: prepRegs shim v1 (fails — copy-paste bug, no return cleanup)
    ├── interceptor_full_attempt.js    # Most complete attempt (fails — no rbx/rcx cleanup)
    ├── interceptor_syscall_level.js   # Syscall/RawSyscall6 level hooks (fails — no redirect)
    ├── interceptor_server_v1.js       # Server with global flag dispatch (fails — thread-unsafe)
    ├── interceptor_client_v1.js       # Client with global flag dispatch (fails — thread-unsafe)
    ├── prepRegs.asm               # NASM ABI shim (3-arg register shuffle)
    ├── prepRegs2.asm              # NASM ABI shim (multiple named variants)
    ├── prepRegs.s                 # Go plan9 assembly approach (can't inject via Frida)
    ├── wrapper.asm                # Various assembly wrapper experiments
    └── wrapper.go                 # Go CGo wrapper experiment
```

## How It Works

The corrected interceptors (`interceptor_server.js`, `interceptor_client.js`) use this approach:

1. **Find Go symbols** — `Module.enumerateSymbols()` locates `syscall.socket`, `syscall.bind`, etc. in the Go binary.
2. **Replace with `ret` trampoline** — `Interceptor.replace()` swaps each Go function with a dynamically-allocated single-instruction `ret` (no-op).
3. **Read Go ABI registers in `onEnter`** — Before the trampoline runs, save arguments from Go ABI positions (`rax`, `rbx`, `rcx`, `rdi`, `rsi`).
4. **Call VCL in `onLeave`** — After the trampoline returns, call the corresponding LDP function with the saved arguments.
5. **Set Go return convention** — Set `rax=result`, `rbx=0`, `rcx=0` (success) or `rax=-1`, `rbx=0`, `rcx=errno` (error).

```
Go: syscall.socket(domain=2, type=1, proto=0)
  │ rax=2, rbx=1, rcx=0
  ├─ onEnter: save _domain=rax, _type=rbx, _protocol=rcx
  ├─ trampoline: ret (no-op)
  ├─ onLeave: ret = ldp.socket(2, 1, 0) → fd=3
  │           rax=3, rbx=0, rcx=0
  └─ Go sees: fd=3, errno=0 ✓
```

## Quick Start

```bash
# Build test binaries (on Linux x86_64 with Go installed)
cd test/
go build -o echo_server echo_server.go
go build -o echo_client echo_client.go

# Test without VCL (verify hooks work)
frida ./echo_server -l ../interceptor_server.js --no-pause

# Test with VPP/VCL
VCL_CONFIG=/tmp/server-share/vcl.conf frida ./echo_server -l ../interceptor_server.js --no-pause
```

See [test/README.md](test/README.md) for detailed instructions including Docker/HST setup.

## Key Bugs Fixed

All previous attempts failed due to three fundamental issues:

| Bug | Root Cause | Fix |
|-----|-----------|-----|
| Go return values corrupted | Only `rax` was set; `rbx`/`rcx` left as garbage | Always set `rbx=0, rcx=0` (or `rcx=errno`) in `onLeave` |
| Thread-unsafe dispatch | Global flag to identify which syscall is active | Per-invocation state via `this._xxx` in Frida's `onEnter` |
| No assembly shim needed | prepRegs.asm + two-step replace+attach was fragile | Single `ret` trampoline + JS-side register read/write |

See [docs/failed_attempt_analysis.md](docs/failed_attempt_analysis.md) for the full breakdown.

## Requirements

- Linux x86_64
- VPP with `libvcl_ldpreload.so` installed at `/usr/lib/libvcl_ldpreload.so`
- Frida (`pip3 install frida frida-tools`)
- Go binary built **without stripping** (no `-ldflags="-s -w"`) — Frida needs symbols
