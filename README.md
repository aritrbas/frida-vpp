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

**Status:** Full end-to-end working — TCP echo and HTTP (client↔server) over VPP VCL.

## Repository Structure

```
frida-vpp/
├── interceptor.js                 # ★ Unified Frida script — works for ANY Go binary (server or client)
├── interceptor_server.js          # Earlier server-only script (working, kept for reference)
├── interceptor_client.js          # Earlier client-only script (working, kept for reference)
├── docs/
│   ├── interceptor_architecture.md   # Full technical design & architecture of interceptor.js
│   ├── abi_analysis.md               # Go ABI vs System V ABI — deep register & stack analysis
│   └── debugging.md                  # All failed attempts, debugging sessions, and bug fixes
├── test/
│   ├── echo_server.go             # TCP echo server for testing
│   ├── echo_client.go             # TCP echo client for testing
│   ├── http_server.go             # Raw TCP HTTP server for testing
│   ├── http_client.go             # Raw TCP HTTP client for testing
│   ├── run_tests.sh               # Automated test runner (both echo and HTTP)
│   └── README.md                  # Build, run, and test instructions
└── experiments/                   # All previous failed attempts (for reference)
    ├── interceptor2.js            # Attempt: Hook libc symbols (fails — Go bypasses libc)
    ├── interceptor3.js            # Attempt: Direct replace Go symbols with LDP (fails — ABI mismatch)
    ├── interceptor4.js            # Attempt: Hook RawSyscall6 (fails — wrong register indexing)
    ├── interceptor_v1.js          # Attempt: prepRegs per-syscall shims (fails — no rbx/rcx cleanup)
    ├── interceptor_v2.js          # Attempt: Syscall/RawSyscall6 level hooks (fails — no redirect)
    ├── interceptor_server_v1.js   # Attempt: Server with global flag dispatch (fails — thread-unsafe)
    ├── interceptor_client_v1.js   # Attempt: Client with global flag dispatch (fails — thread-unsafe)
    ├── prepRegs.asm               # NASM ABI shim (3-arg register shuffle)
    └── prepRegs2.asm              # NASM ABI shim (multiple named variants)
```

### Interceptor Scripts

| Script | Scope | Description |
|--------|-------|-------------|
| **`interceptor.js`** | Universal | **Latest and recommended.** Auto-detects Go binary, 17+ syscalls, epoll-based blocking, VCL library auto-resolution, configurable log verbosity. Works for both servers and clients. |
| `interceptor_server.js` | Server only | Earlier working script. Hardcodes `moduleName = 'echo_server'`. Hooks 11 syscalls. |
| `interceptor_client.js` | Client only | Earlier working script. Hardcodes `moduleName = 'echo_client'`. Hooks 9 syscalls (no accept/listen). |

All three scripts use the same core architecture (see [How It Works](#how-it-works)). The unified `interceptor.js` supersedes the other two.

## How It Works

The interceptor uses this approach:

1. **Auto-detect Go binary** — scans loaded modules for Go symbols (`syscall.*`, `runtime.*`).
2. **Find Go syscall symbols** — `Process.getModuleByName(name).enumerateSymbols()` locates `syscall.socket`, `syscall.bind`, `syscall.read`, `syscall.write`, `syscall.Close`, etc.
3. **Replace with `ret` trampoline** — `Interceptor.replace()` swaps each Go function with a dynamically-allocated single-instruction `ret` (no-op).
4. **Read Go ABI registers in `onEnter`** — Before the trampoline runs, save arguments from Go ABI positions (`rax`, `rbx`, `rcx`, `rdi`, `rsi`).
5. **Call VCL in `onLeave`** — After the trampoline returns, call the corresponding LDP function with the saved arguments.
6. **Set Go return convention** — Set `rax=result`, `rbx=0`, `rcx=0` (success) or `rax=-1`, `rbx=err.itab`, `rcx=err.data` (error) using `go:itab.syscall.Errno,error` for arbitrary errno values.
7. **Conditional VCL loading** — If `VCL_CONFIG` is not set, the script runs in passthrough mode (no hooks installed, syscalls go to kernel).

```
Go: syscall.socket(domain=2, type=1, proto=0)
  │ rax=2, rbx=1, rcx=0
  ├─ onEnter: save _domain=rax, _type=rbx, _protocol=rcx
  ├─ trampoline: ret (no-op)
  ├─ onLeave: ret = ldp.socket(2, 1, 0) → fd=32 (VCL fake fd = vlsh+32)
  │           rax=32, rbx=0, rcx=0
  └─ Go sees: fd=32, errno=0 ✓

Go: syscall.read(fd=32, buf, len)
  │ rax=32, rbx=buf_ptr, rcx=len
  ├─ onEnter: save _fd=32, _buf=buf_ptr, _len=len
  ├─ trampoline: ret (no-op)
  ├─ onLeave: ret = ldp.read(32, buf, len)  ← LDP routes fd≥32 to VCL
  │           if EAGAIN on VCL fd → ldp.epoll_wait(EPOLLIN, 5s)
  │           (epoll_wait processes VCL message queue, then retry)
  └─ Go sees: n bytes read ✓
```

### Why `read`/`write`/`close` Must Be Hooked

LDP assigns fake fd numbers to VCL sessions (`fd = vlsh + 32`). These do not exist as kernel file descriptors. If Go calls the kernel's `read(fd=32, ...)` directly, the kernel returns `EBADF`. Hooking `syscall.read`, `syscall.write`, and `syscall.Close` ensures all I/O goes through LDP, which internally routes based on the fd value:
- `fd ≥ 32` → VCL session path
- `fd < 32` → real kernel fd path (libc passthrough)

### Supported Syscalls (17)

`socket`, `bind`, `listen`, `accept4`, `accept`, `connect`, `setsockopt`, `getsockopt`, `getsockname`, `getpeername`, `read`, `write`, `close`, `shutdown`, `fcntl`, `epoll_ctl`, `epoll_wait`

For the full technical architecture, see [docs/interceptor_architecture.md](docs/interceptor_architecture.md).

## Quick Start

### Build Test Binaries

```bash
cd test/
go build -o echo_server echo_server.go
go build -o echo_client echo_client.go
go build -o http_server http_server.go
go build -o http_client http_client.go
cd ..
```

**Important:** Do NOT use `-ldflags="-s -w"` — Frida needs the Go symbols.

### Set Up Environment

```bash
export VPP_LIB=/home/aritrbas/vpp/build-root/install-vpp_debug-native/vpp/lib/x86_64-linux-gnu
export LD_LIBRARY_PATH=$VPP_LIB
```

### Test Without VCL (Passthrough Mode)

Verify hooks fire correctly before adding VPP to the mix:

```bash
frida -f ./test/echo_server -l interceptor.js
# Expected: "[*] VCL_CONFIG not set — passthrough mode"
```

### Test With VPP/VCL

VPP must be running first. Create VCL config files (only needed once):

```bash
mkdir -p /tmp/server-share /tmp/client-share
printf 'vcl {\n  rx-fifo-size 4000000\n  tx-fifo-size 4000000\n  app-scope-local\n  app-scope-global\n  use-mq-eventfd\n  app-socket-api /run/vpp/app_ns_sockets/default\n}\n' \
  > /tmp/server-share/vcl.conf
cp /tmp/server-share/vcl.conf /tmp/client-share/vcl.conf
```

#### Echo (TCP) Test

```bash
# Terminal 1 — server
VCL_CONFIG=/tmp/server-share/vcl.conf frida -f ./test/echo_server -l interceptor.js

# Terminal 2 — client
VCL_CONFIG=/tmp/client-share/vcl.conf \
  frida -f ./test/echo_client -l interceptor.js \
  -- 127.0.0.1:9876 "hello vcl"
# Expected: [client] Echo: hello vcl
```

#### HTTP Test

```bash
# Terminal 1 — server
VCL_CONFIG=/tmp/server-share/vcl.conf frida -f ./test/http_server -l interceptor.js -- 8080

# Terminal 2 — client
VCL_CONFIG=/tmp/client-share/vcl.conf \
  frida -f ./test/http_client -l interceptor.js \
  -- 127.0.0.1:8080 /
# Expected: PASS: got HTTP 200 OK
```

#### Automated Test Runner

```bash
cd test/
./run_tests.sh          # run all tests
./run_tests.sh echo     # echo test only
./run_tests.sh http     # HTTP test only
```

See [test/README.md](test/README.md) for detailed instructions including Docker/HST setup.

## Key Bugs Fixed

All previous experimental attempts failed and multiple debugging sessions were needed to achieve end-to-end working interception. See [docs/debugging.md](docs/debugging.md) for the full chronological analysis.

| Bug | Symptom | Root Cause | Fix |
|-----|---------|-----------|-----|
| Go return values corrupted | Successful VCL calls reported as errors | Only `rax` set; `rbx`/`rcx` left as garbage from C call | Always set `rbx`/`rcx` using `go:itab.syscall.Errno,error` + heap-allocated errno slots |
| Thread-unsafe dispatch | Wrong LDP function called under concurrency | Global flag to identify active syscall; goroutines race on it | Per-invocation state via `this._` in Frida's `onEnter` |
| Assembly shim fragility | Stack corruption, return value undefined | prepRegs.asm + two-step replace+attach | Single `ret` trampoline + JS-side register read/write |
| accept4 EBADF | "bad file descriptor" from Go Accept | LDP fake fds (≥32); Go tried kernel epoll on fake fd | Make accept4 blocking (spin-wait EAGAIN) |
| read/write EBADF | Data transfer fails silently | Kernel read/write on VCL fake fds → EBADF | Hook `syscall.read`, `write`, `Close` → route through LDP |
| MPTCP duplicate listeners | EADDRINUSE on listen() | Go 1.21+ creates proto=262 (MPTCP) + regular TCP socket | Reject proto=262 with EPROTONOSUPPORT |
| IPv6 dual-stack EADDRINUSE | listen() fails | VPP creates IPv4+IPv6 companion listeners | Set `IPV6_V6ONLY=1` before `ldp.listen()` on IPv6 sockets |
| connect stuck forever | Client hangs | `VPPCOM_ATTR_GET_ERROR` is a VPP stub (always returns 0); `ldp.poll` blocks JS thread | Use `ldp.epoll_wait(EPOLLOUT)` to wait for session READY |
| VCL MQ starvation | write ENOTCONN, read EAGAIN forever | `vppcom_session_write/read` don't process MQ; SESSION_CONNECTED unread | Use `ldp.epoll_wait()` as MQ pump |
| IPv4/IPv6 mismatch | "no route" from VPP connect | VPP doesn't cross-match IPv4 connect → IPv6 listener | Use `"tcp4"` in Go binaries |
| Go runtime poller bypass | getsockopt(SO_ERROR) spam at 100% CPU | Go's poller uses raw syscalls — can't register VCL fake fds with kernel epoll | Handle async connect entirely in Frida hook |
| goErrFromErrno panic | nil pointer dereference in Go error formatting | `syscall.Errno` has pointer receivers — data must be `*Errno`, not inline value | Allocate 8-byte heap slot per errno |
| findLdpSym returns null | No LDP functions resolved | Module registered under versioned soname `.so.26.06` | Search modules for 'ldpreload' substring |
| Goroutine stack overflow | SIGSEGV in stackpoolalloc | epoll NativeFunction calls overflow 8KB goroutine stack | Use spin-wait for accept/server-side goroutines |
| Frida 17 API breakage | Hooks silently not installed | `Module.enumerateSymbols()` callback form removed; `findExportByName` static form removed; `getEnvironmentVariable` removed | Use array-returning APIs; `findExport()` helper; libc `getenv()` via NativeFunction |

## Requirements

- Linux x86_64
- VPP built from source (e.g., at `/home/aritrbas/vpp`); `libvcl_ldpreload.so` in the build tree
- `LD_LIBRARY_PATH` pointing at VPP's lib directory (see Quick Start above)
- Frida 17+ (`pip3 install frida frida-tools`)
- Go binary built **without stripping** (no `-ldflags="-s -w"`) — Frida needs symbols
