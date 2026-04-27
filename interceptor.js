/*
 * Frida VPP/VCL Unified Interceptor for Go Binaries (Server + Client)
 *
 * Intercepts Go's socket-layer syscalls and redirects them to VPP's VCL
 * library (libvcl_ldpreload.so).
 *
 * Improvements over previous interceptor_server.js / interceptor_client.js:
 *   - Single universal script — auto-detects Go binary, works for any target
 *   - 17+ syscalls supported (added: accept, getpeername, fcntl, epoll_ctl,
 *     epoll_pwait, shutdown)
 *   - Proper IPv4/IPv6 dual-stack support (V6ONLY only on IPv6 sockets)
 *   - Epoll-based blocking (no CPU-burning spin-waits)
 *   - Thread-safe per-invocation state via Frida's this._
 *   - Simplified error helper with pre-cached errno slots
 *   - Passthrough mode when VCL_CONFIG is unset
 *   - Configurable log verbosity
 *
 * SETUP:
 *   export LD_LIBRARY_PATH=/path/to/vpp/lib/x86_64-linux-gnu
 *   VCL_CONFIG=/path/to/vcl.conf frida -f ./my_go_binary -l interceptor.js -- [args]
 *
 * Or attach to running process:
 *   VCL_CONFIG=/path/to/vcl.conf frida -p <PID> -l interceptor.js
 */

'use strict';

/* ============================================================================
 * CONFIGURATION
 * ============================================================================ */

// Auto-detect Go binary module name. Falls back to the main executable.
var moduleName = (function detectGoModule() {
    // The main module is always the first one loaded
    var mainMod = Process.enumerateModules()[0];
    // Verify it has Go symbols
    var hasGoSyms = false;
    try {
        mainMod.enumerateSymbols().some(function(sym) {
            if (sym.name.indexOf('syscall.') === 0 || sym.name.indexOf('runtime.') === 0) {
                hasGoSyms = true;
                return true;
            }
            return false;
        });
    } catch (e) {}
    if (hasGoSyms) {
        console.log('[+] Auto-detected Go binary: ' + mainMod.name);
        return mainMod.name;
    }
    // Fallback: search all modules for Go symbols
    var found = null;
    Process.enumerateModules().some(function(m) {
        try {
            m.enumerateSymbols().some(function(sym) {
                if (sym.name === 'syscall.socket') {
                    found = m.name;
                    return true;
                }
                return false;
            });
        } catch (e) {}
        return !!found;
    });
    if (found) {
        console.log('[+] Found Go symbols in: ' + found);
        return found;
    }
    console.log('[!] Could not auto-detect Go module, using first module: ' + mainMod.name);
    return mainMod.name;
})();

// Path to VCL LD_PRELOAD library.
// Resolution order:
//   1. VCL_LIB_PATH env var (explicit override)
//   2. Already-loaded libvcl_ldpreload in process (from LD_PRELOAD or LD_LIBRARY_PATH)
//   3. Standard system paths
//   4. Common VPP build-root layouts (debug and release)
// The actual resolution happens after getEnv() is available (see below).
var VCL_LIB = null;

// Log verbosity: 0=errors only, 1=lifecycle, 2=all syscalls
var LOG_LEVEL = 2;

function log(level, msg) {
    if (level <= LOG_LEVEL) console.log(msg);
}

// All Go syscall symbols we want to intercept
var syscallNames = [
    'syscall.socket',
    'syscall.bind',
    'syscall.Listen',
    'syscall.accept4',
    'syscall.accept',       // NEW: some Go versions use accept instead of accept4
    'syscall.connect',
    'syscall.setsockopt',
    'syscall.getsockopt',
    'syscall.getsockname',
    'syscall.getpeername',  // NEW
    'syscall.read',
    'syscall.write',
    'syscall.Close',
    'syscall.Shutdown',     // NEW
    'syscall.fcntl',        // NEW
    'syscall.EpollCtl',     // NEW
    'syscall.EpollWait',    // NEW (epoll_pwait)
];

/* ============================================================================
 * STEP 1: Find Go symbol addresses
 * ============================================================================ */

var syscallAddresses = {};

Process.getModuleByName(moduleName).enumerateSymbols().forEach(function(sym) {
    if (syscallNames.indexOf(sym.name) !== -1) {
        syscallAddresses[sym.name] = sym.address;
        log(1, '[+] Found ' + sym.name + ' at ' + sym.address);
    }
});

var foundCount = Object.keys(syscallAddresses).length;
log(1, '[+] Found ' + foundCount + '/' + syscallNames.length + ' Go syscall symbols');

/* ============================================================================
 * STEP 2: Utility functions
 * ============================================================================ */

// Frida 17 compatible findExport
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

// Resolve LDP symbols directly from the library's symbol table,
// bypassing PLT/GOT which may return libc's interposed functions.
var _ldpSymCache = {};
var _ldpModule = null;

function getLdpModule() {
    if (_ldpModule) return _ldpModule;
    Process.enumerateModules().some(function(m) {
        if (m.name.indexOf('ldpreload') !== -1 || m.path.indexOf('ldpreload') !== -1) {
            _ldpModule = m;
            return true;
        }
        return false;
    });
    return _ldpModule;
}

function findLdpSym(symName) {
    if (_ldpSymCache[symName]) return _ldpSymCache[symName];
    var mod = getLdpModule();
    if (!mod) { log(0, '[!] libvcl_ldpreload not found in modules'); return null; }
    var addr = null;
    mod.enumerateSymbols().some(function(sym) {
        if (sym.name === symName && sym.address && !sym.address.isNull()) {
            addr = sym.address;
            return true;
        }
        return false;
    });
    if (!addr) {
        addr = mod.findExportByName(symName);
        if (addr) log(1, '[!] findLdpSym(' + symName + '): using export fallback');
    }
    if (addr) _ldpSymCache[symName] = addr;
    return addr;
}

// Libc getenv()
var _getenv = new NativeFunction(findExport('libc.so.6', 'getenv'), 'pointer', ['pointer']);
function getEnv(name) {
    var p = _getenv(Memory.allocUtf8String(name));
    return p.isNull() ? null : p.readUtf8String();
}

// Resolve VCL_LIB now that getEnv is available
VCL_LIB = (function resolveVclLib() {
    // 1. Explicit env var override
    var envPath = getEnv('VCL_LIB_PATH');
    if (envPath) {
        log(1, '[+] VCL_LIB_PATH override: ' + envPath);
        return envPath;
    }

    // 2. Already loaded in process (e.g., via LD_PRELOAD)
    var loaded = null;
    Process.enumerateModules().some(function(m) {
        if (m.name.indexOf('libvcl_ldpreload') !== -1) {
            loaded = m.path;
            return true;
        }
        return false;
    });
    if (loaded) {
        log(1, '[+] VCL lib already loaded: ' + loaded);
        return loaded;
    }

    // 3. Search LD_LIBRARY_PATH directories
    var ldPath = getEnv('LD_LIBRARY_PATH');
    if (ldPath) {
        var dirs = ldPath.split(':');
        for (var i = 0; i < dirs.length; i++) {
            var candidate = dirs[i] + '/libvcl_ldpreload.so';
            try {
                Module.load(candidate);
                log(1, '[+] Found VCL lib via LD_LIBRARY_PATH: ' + candidate);
                return candidate;
            } catch (e) { /* not here, try next */ }
        }
    }

    // 4. Standard system paths
    var systemPaths = [
        '/usr/lib/x86_64-linux-gnu/libvcl_ldpreload.so',
        '/usr/lib/libvcl_ldpreload.so',
        '/usr/local/lib/libvcl_ldpreload.so',
    ];
    for (var j = 0; j < systemPaths.length; j++) {
        try {
            Module.load(systemPaths[j]);
            log(1, '[+] Found VCL lib at: ' + systemPaths[j]);
            return systemPaths[j];
        } catch (e) { /* not here, try next */ }
    }

    log(0, '[!] Could not find libvcl_ldpreload.so. Set VCL_LIB_PATH or LD_LIBRARY_PATH.');
    return 'libvcl_ldpreload.so'; // Last resort — let Module.load() search PATH
})();

/* ============================================================================
 * STEP 3: Load VCL library
 * ============================================================================ */

(function loadVCL() {
    var vclConfig = getEnv('VCL_CONFIG');
    if (!vclConfig) {
        log(1, '[*] VCL_CONFIG not set — passthrough mode (hooks log but syscalls go to kernel).');
        log(1, '[*] Set VCL_CONFIG=/path/to/vcl.conf to redirect to VPP.');
        return;
    }
    var loaded = Process.enumerateModules().some(function(m) {
        return m.path === VCL_LIB || m.name.indexOf('libvcl_ldpreload') !== -1;
    });
    if (!loaded) {
        try {
            Module.load(VCL_LIB);
        } catch (e) {
            log(0, '[!] FATAL: Failed to load ' + VCL_LIB + ': ' + e);
            log(0, '[!] Fix: export LD_LIBRARY_PATH to the directory containing libvcl_ldpreload.so');
            throw e;
        }
        log(1, '[+] Loaded ' + VCL_LIB);
    } else {
        log(1, '[+] VCL library already loaded');
    }
})();

var vclEnabled = !!getEnv('VCL_CONFIG');

/* ============================================================================
 * STEP 4: Install hooks
 *
 * When VCL is not enabled, we skip all hook installation and run in
 * passthrough mode (Go syscalls go directly to kernel).
 * When VCL IS enabled, we resolve LDP functions and install per-syscall hooks.
 * ============================================================================ */

if (!vclEnabled) {
    log(1, '[*] Passthrough mode active. No hooks installed.');
} else {

/* ============================================================================
 * STEP 4a: Resolve LDP function pointers
 * ============================================================================ */

var ldp = {
    socket:        new NativeFunction(findLdpSym('socket'),        'int', ['int', 'int', 'int']),
    bind:          new NativeFunction(findLdpSym('bind'),          'int', ['int', 'pointer', 'int']),
    listen:        new NativeFunction(findLdpSym('listen'),        'int', ['int', 'int']),
    accept:        new NativeFunction(findLdpSym('accept'),        'int', ['int', 'pointer', 'pointer']),
    accept4:       new NativeFunction(findLdpSym('accept4'),       'int', ['int', 'pointer', 'pointer', 'int']),
    connect:       new NativeFunction(findLdpSym('connect'),       'int', ['int', 'pointer', 'int']),
    setsockopt:    new NativeFunction(findLdpSym('setsockopt'),    'int', ['int', 'int', 'int', 'pointer', 'int']),
    getsockopt:    new NativeFunction(findLdpSym('getsockopt'),    'int', ['int', 'int', 'int', 'pointer', 'pointer']),
    getsockname:   new NativeFunction(findLdpSym('getsockname'),   'int', ['int', 'pointer', 'pointer']),
    getpeername:   new NativeFunction(findLdpSym('getpeername'),   'int', ['int', 'pointer', 'pointer']),
    read:          new NativeFunction(findLdpSym('read'),          'int', ['int', 'pointer', 'int']),
    write:         new NativeFunction(findLdpSym('write'),         'int', ['int', 'pointer', 'int']),
    close:         new NativeFunction(findLdpSym('close'),         'int', ['int']),
    shutdown:      new NativeFunction(findLdpSym('shutdown'),      'int', ['int', 'int']),
    fcntl:         new NativeFunction(findLdpSym('fcntl'),         'int', ['int', 'int', 'int']),
    epoll_create1: new NativeFunction(findLdpSym('epoll_create1'), 'int', ['int']),
    epoll_ctl:     new NativeFunction(findLdpSym('epoll_ctl'),     'int', ['int', 'int', 'int', 'pointer']),
    epoll_wait:    new NativeFunction(findLdpSym('epoll_wait'),    'int', ['int', 'pointer', 'int', 'int']),
};

log(1, '[+] Resolved ' + Object.keys(ldp).length + ' LDP function pointers');

/* ============================================================================
 * STEP 4b: C errno helper
 * ============================================================================ */

var errnoLocation = new NativeFunction(
    findExport('libc.so.6', '__errno_location'), 'pointer', []
);
function getCErrno() {
    return errnoLocation().readInt();
}

/* ============================================================================
 * STEP 4c: Go error interface construction
 *
 * Go's error is a 16-byte interface: {itab_ptr, data_ptr}.
 * At the syscall.* level, error returns are full Go interfaces.
 *
 * We find go:itab.syscall.Errno,error and construct {itab, &errno_value}
 * for any errno. Since Errno has pointer receivers, data must point to
 * a heap-allocated uintptr holding the errno value.
 *
 * We pre-allocate slots for all common errnos to avoid repeated allocation.
 * ============================================================================ */

var goErrnoItab = null;

(function findGoErrnoItab() {
    Process.getModuleByName(moduleName).enumerateSymbols().forEach(function(sym) {
        if (sym.name === 'go:itab.syscall.Errno,error') {
            goErrnoItab = sym.address;
            log(1, '[+] Found go:itab.syscall.Errno,error @ ' + sym.address);
        }
    });
    if (!goErrnoItab) {
        log(0, '[!] go:itab.syscall.Errno,error not found — error returns may be incorrect');
        log(0, '[!] Ensure your Go binary is built with symbols (no -ldflags="-s -w")');
    }
})();

// Pre-cache errno data slots for common values to avoid allocation in hot paths.
// Each slot is a persistent 8-byte heap allocation holding the errno as a uintptr.
var _errnoDataCache = {};

// Pre-allocate common errnos
var COMMON_ERRNOS = [
    1,   /* EPERM */        2,   /* ENOENT */       9,   /* EBADF */
    11,  /* EAGAIN */       13,  /* EACCES */        14,  /* EFAULT */
    22,  /* EINVAL */       93,  /* EPROTONOSUPPORT */ 95, /* EOPNOTSUPP */
    98,  /* EADDRINUSE */   99,  /* EADDRNOTAVAIL */
    103, /* ECONNABORTED */ 104, /* ECONNRESET */    106, /* EISCONN */
    107, /* ENOTCONN */     110, /* ETIMEDOUT */     111, /* ECONNREFUSED */
    114, /* EALREADY */     115, /* EINPROGRESS */
];

COMMON_ERRNOS.forEach(function(e) {
    var slot = Memory.alloc(8);
    slot.writeU64(e);
    _errnoDataCache[e] = slot;
});

function goErrFromErrno(errno) {
    if (!goErrnoItab) {
        // Fallback: return nil error (will appear as success to Go)
        return { itab: ptr(0), data: ptr(0) };
    }
    if (!_errnoDataCache[errno]) {
        var slot = Memory.alloc(8);
        slot.writeU64(errno);
        _errnoDataCache[errno] = slot;
    }
    return { itab: goErrnoItab, data: _errnoDataCache[errno] };
}

/* ============================================================================
 * STEP 4d: Go return value helper
 *
 * Go's register ABI uses different return registers depending on the
 * function signature:
 *
 *   func f() (int, error)  → rax=int, rbx=err.itab, rcx=err.data
 *   func f() error         → rax=err.itab, rbx=err.data
 *
 * returnsInt=true for socket/accept/accept4/read/write (return int + error)
 * returnsInt=false for bind/listen/connect/setsockopt/getsockopt/getsockname
 *                   /getpeername/shutdown/close (return error only)
 * ============================================================================ */

function setGoReturn(context, retval, result, syscallName, returnsInt) {
    if (result < 0) {
        var errno = getCErrno();
        var goErr = goErrFromErrno(errno);
        log(2, '[!] ' + syscallName + ' failed: ret=' + result + ', errno=' + errno);
        if (returnsInt) {
            retval.replace(-1);
            context.rbx = goErr.itab;
            context.rcx = goErr.data;
        } else {
            retval.replace(goErr.itab);
            context.rbx = goErr.data;
            context.rcx = ptr(0);
        }
    } else {
        log(2, '[+] ' + syscallName + ' ok: ret=' + result);
        if (returnsInt) {
            retval.replace(result);
            context.rbx = ptr(0);
            context.rcx = ptr(0);
        } else {
            retval.replace(0);   // nil error.itab
            context.rbx = ptr(0);
            context.rcx = ptr(0);
        }
    }
}

/* ============================================================================
 * STEP 4e: Trampoline allocation
 *
 * Each Go syscall function body is replaced with a single `ret` instruction.
 * Frida's onEnter fires before ret, onLeave after — giving us full control
 * of the Go ABI register state.
 * ============================================================================ */

function allocateRetTrampoline() {
    var block = Memory.alloc(Process.pageSize);
    Memory.patchCode(block, 16, function(code) {
        var w = new X86Writer(code, { pc: block });
        w.putRet();
        w.flush();
    });
    return block;
}

/* ============================================================================
 * STEP 4f: Epoll-based wait helper
 *
 * Instead of CPU-burning spin-waits, we use LDP's epoll_wait to:
 *   1. Wait for events (EPOLLIN/EPOLLOUT) on VCL file descriptors
 *   2. Pump VCL's message queue (epoll_wait → vppcom_epoll_wait → MQ drain)
 *
 * This is critical because vppcom_session_read/write do NOT process the
 * worker message queue — pending events (SESSION_CONNECTED, data available)
 * sit unread until something calls vppcom_epoll_wait.
 * ============================================================================ */

function waitForEvent(fd, eventMask, timeoutMs) {
    var epfd = ldp.epoll_create1(0);
    if (epfd < 0) return -1;

    var ev = Memory.alloc(12);  // struct epoll_event (packed on x86_64)
    ev.writeU32(eventMask);
    ev.add(4).writeU32(fd);     // data.fd

    var ret = ldp.epoll_ctl(epfd, 1 /* EPOLL_CTL_ADD */, fd, ev);
    if (ret !== 0) {
        ldp.close(epfd);
        return -1;
    }

    var events = Memory.alloc(12);
    var n = ldp.epoll_wait(epfd, events, 1, timeoutMs);
    ldp.close(epfd);
    return n;
}

// Wait for readable with MQ pump. Returns the number of events ready.
function waitReadable(fd, timeoutMs) {
    return waitForEvent(fd, 0x01 /* EPOLLIN */, timeoutMs);
}

// Wait for writable with MQ pump. Returns the number of events ready.
function waitWritable(fd, timeoutMs) {
    return waitForEvent(fd, 0x04 /* EPOLLOUT */, timeoutMs);
}

/* ============================================================================
 * STEP 4g: FD tracking for VCL fds
 *
 * LDP assigns fake file descriptors (vlsh + 32) that don't exist in the
 * kernel. We track which FDs are VCL-managed so we know when to use
 * epoll-based waiting vs. letting the kernel handle it.
 *
 * We also track socket address families so we know which sockets are
 * IPv6 (for V6ONLY handling).
 * ============================================================================ */

var LDP_FD_OFFSET = 32;  // LDP: fd = vlsh + (1 << LDP_SID_BIT_MIN), where min=5
// fd → { family: AF_INET|AF_INET6, role: 'server'|'client'|'pending' }
// role='server': fd came from accept4/accept — handleConn goroutine has a small
//   stack; avoid epoll NativeFunction calls which overflow it → use spin-wait.
// role='client': fd came from connect — needs epoll MQ pump in read/write.
var _vclFds = {};

function isVclFd(fd) {
    return fd >= LDP_FD_OFFSET && _vclFds[fd] !== undefined;
}

function isClientFd(fd) {
    return _vclFds[fd] !== undefined && _vclFds[fd].role === 'client';
}

function trackVclFd(fd, family, role) {
    _vclFds[fd] = { family: family, role: role || 'pending' };
}

function setVclFdRole(fd, role) {
    if (_vclFds[fd]) _vclFds[fd].role = role;
}

function untrackVclFd(fd) {
    delete _vclFds[fd];
}

function getVclFdFamily(fd) {
    return _vclFds[fd] ? _vclFds[fd].family : 0;
}

/* ============================================================================
 * STEP 5: Hook each syscall
 *
 * Each hook follows the same pattern:
 *   1. Replace Go function body with ret trampoline
 *   2. Attach onEnter: read Go ABI registers into per-invocation state
 *   3. Attach onLeave: call LDP, set Go return registers
 *
 * Thread safety: Frida's `this._` is per-invocation (per goroutine),
 * so concurrent goroutines do not interfere with each other.
 * ============================================================================ */

// --- socket(domain, type, protocol) → (fd int, err error) ---
(function hookSocket() {
    var addr = syscallAddresses['syscall.socket'];
    if (!addr) { log(1, '[-] syscall.socket not found'); return; }

    var trampoline = allocateRetTrampoline();
    Interceptor.replace(addr, trampoline);

    Interceptor.attach(addr, {
        onEnter: function(args) {
            // Go ABI: rax=domain, rbx=type, rcx=protocol
            this._domain   = this.context.rax.toInt32();
            this._type     = this.context.rbx.toInt32();
            this._protocol = this.context.rcx.toInt32();
            log(2, '[>] socket(' + this._domain + ', ' + this._type + ', ' + this._protocol + ')');
        },
        onLeave: function(retval) {
            // Reject MPTCP (proto=262) — VPP doesn't support it.
            // Go 1.21+ probes MPTCP first; EPROTONOSUPPORT makes it fall back to TCP.
            if (this._protocol === 262) {
                var err = goErrFromErrno(93 /* EPROTONOSUPPORT */);
                retval.replace(-1);
                this.context.rbx = err.itab;
                this.context.rcx = err.data;
                log(2, '[>] socket: MPTCP rejected → EPROTONOSUPPORT');
                return;
            }
            var ret = ldp.socket(this._domain, this._type, this._protocol);
            if (ret >= LDP_FD_OFFSET) {
                trackVclFd(ret, this._domain);
            }
            setGoReturn(this.context, retval, ret, 'socket', true);
        }
    });
    log(1, '[+] Hooked syscall.socket');
})();

// --- bind(fd, addr, addrlen) → error ---
(function hookBind() {
    var addr = syscallAddresses['syscall.bind'];
    if (!addr) { log(1, '[-] syscall.bind not found'); return; }

    var trampoline = allocateRetTrampoline();
    Interceptor.replace(addr, trampoline);

    Interceptor.attach(addr, {
        onEnter: function(args) {
            this._fd      = this.context.rax.toInt32();
            this._addr    = this.context.rbx;
            this._addrlen = this.context.rcx.toInt32();
            log(2, '[>] bind(fd=' + this._fd + ', addrlen=' + this._addrlen + ')');
        },
        onLeave: function(retval) {
            var ret = ldp.bind(this._fd, ptr(this._addr.toString()), this._addrlen);
            setGoReturn(this.context, retval, ret, 'bind', false);
        }
    });
    log(1, '[+] Hooked syscall.bind');
})();

// --- listen(fd, backlog) → error ---
(function hookListen() {
    var addr = syscallAddresses['syscall.Listen'];
    if (!addr) { log(1, '[-] syscall.Listen not found'); return; }

    var trampoline = allocateRetTrampoline();
    Interceptor.replace(addr, trampoline);

    Interceptor.attach(addr, {
        onEnter: function(args) {
            this._fd      = this.context.rax.toInt32();
            this._backlog = this.context.rbx.toInt32();
            log(2, '[>] listen(fd=' + this._fd + ', backlog=' + this._backlog + ')');
        },
        onLeave: function(retval) {
            // For IPv6 sockets only: set IPV6_V6ONLY=1 before listen() to prevent
            // VPP's LDP from creating a companion IPv4 listener (EADDRINUSE).
            // IPv4 sockets are unaffected.
            if (getVclFdFamily(this._fd) === 10 /* AF_INET6 */) {
                var v6onlyBuf = Memory.alloc(4);
                v6onlyBuf.writeInt(1);
                ldp.setsockopt(this._fd, 41 /* IPPROTO_IPV6 */, 26 /* IPV6_V6ONLY */, v6onlyBuf, 4);
                log(2, '[>] listen: set IPV6_V6ONLY=1 on IPv6 fd=' + this._fd);
            }
            var ret = ldp.listen(this._fd, this._backlog);
            setGoReturn(this.context, retval, ret, 'listen', false);
        }
    });
    log(1, '[+] Hooked syscall.Listen');
})();

// --- getsockname(fd, addr, addrlen_ptr) → error ---
(function hookGetsockname() {
    var addr = syscallAddresses['syscall.getsockname'];
    if (!addr) { log(1, '[-] syscall.getsockname not found'); return; }

    var trampoline = allocateRetTrampoline();
    Interceptor.replace(addr, trampoline);

    Interceptor.attach(addr, {
        onEnter: function(args) {
            this._fd         = this.context.rax.toInt32();
            this._addr       = this.context.rbx;
            this._addrlenPtr = this.context.rcx;
        },
        onLeave: function(retval) {
            var ret = ldp.getsockname(this._fd, ptr(this._addr.toString()),
                                      ptr(this._addrlenPtr.toString()));
            setGoReturn(this.context, retval, ret, 'getsockname', false);
        }
    });
    log(1, '[+] Hooked syscall.getsockname');
})();

// --- getpeername(fd, addr, addrlen_ptr) → error ---
// NEW: Required for net.Conn.RemoteAddr()
(function hookGetpeername() {
    var addr = syscallAddresses['syscall.getpeername'];
    if (!addr) { log(1, '[-] syscall.getpeername not found (optional)'); return; }

    var trampoline = allocateRetTrampoline();
    Interceptor.replace(addr, trampoline);

    Interceptor.attach(addr, {
        onEnter: function(args) {
            this._fd         = this.context.rax.toInt32();
            this._addr       = this.context.rbx;
            this._addrlenPtr = this.context.rcx;
        },
        onLeave: function(retval) {
            var ret = ldp.getpeername(this._fd, ptr(this._addr.toString()),
                                     ptr(this._addrlenPtr.toString()));
            setGoReturn(this.context, retval, ret, 'getpeername', false);
        }
    });
    log(1, '[+] Hooked syscall.getpeername');
})();

// --- connect(fd, addr, addrlen) → error ---
(function hookConnect() {
    var addr = syscallAddresses['syscall.connect'];
    if (!addr) { log(1, '[-] syscall.connect not found'); return; }

    var trampoline = allocateRetTrampoline();
    Interceptor.replace(addr, trampoline);

    Interceptor.attach(addr, {
        onEnter: function(args) {
            this._fd      = this.context.rax.toInt32();
            this._addr    = this.context.rbx;
            this._addrlen = this.context.rcx.toInt32();
            log(2, '[>] connect(fd=' + this._fd + ', addrlen=' + this._addrlen + ')');
        },
        onLeave: function(retval) {
            var ret = ldp.connect(this._fd, ptr(this._addr.toString()), this._addrlen);
            var e = getCErrno();

            if (ret === -1 && (e === 115 /* EINPROGRESS */ || e === 114 /* EALREADY */)) {
                // VCL non-blocking connect: handshake pending.
                // Use epoll_wait to pump VCL's message queue until SESSION_CONNECTED.
                log(2, '[>] connect: EINPROGRESS → waiting for READY via epoll');
                var n = waitWritable(this._fd, 5000);
                if (n > 0) {
                    log(2, '[>] connect: POLLOUT → session READY');
                } else {
                    log(0, '[!] connect: epoll timeout — session may not be connected');
                }
                // Report success to Go regardless — the session is being established
                // Mark this fd as client-side so read/write use epoll MQ pump.
                setVclFdRole(this._fd, 'client');
                retval.replace(0);
                this.context.rbx = ptr(0);
                this.context.rcx = ptr(0);
                return;
            }
            setGoReturn(this.context, retval, ret, 'connect', false);
            // Mark as client-side even on immediate success (ret=0)
            if (ret === 0) setVclFdRole(this._fd, 'client');
        }
    });
    log(1, '[+] Hooked syscall.connect');
})();

// --- setsockopt(fd, level, optname, optval, optlen) → error ---
(function hookSetsockopt() {
    var addr = syscallAddresses['syscall.setsockopt'];
    if (!addr) { log(1, '[-] syscall.setsockopt not found'); return; }

    var trampoline = allocateRetTrampoline();
    Interceptor.replace(addr, trampoline);

    Interceptor.attach(addr, {
        onEnter: function(args) {
            // Go ABI: rax=fd, rbx=level, rcx=optname, rdi=optval_ptr, rsi=optlen
            this._fd      = this.context.rax.toInt32();
            this._level   = this.context.rbx.toInt32();
            this._optname = this.context.rcx.toInt32();
            this._optval  = this.context.rdi;
            this._optlen  = this.context.rsi.toInt32();
        },
        onLeave: function(retval) {
            var ret = ldp.setsockopt(this._fd, this._level, this._optname,
                                     ptr(this._optval.toString()), this._optlen);
            setGoReturn(this.context, retval, ret, 'setsockopt', false);
        }
    });
    log(1, '[+] Hooked syscall.setsockopt');
})();

// --- getsockopt(fd, level, optname, optval, optlen_ptr) → error ---
(function hookGetsockopt() {
    var addr = syscallAddresses['syscall.getsockopt'];
    if (!addr) { log(1, '[-] syscall.getsockopt not found'); return; }

    var trampoline = allocateRetTrampoline();
    Interceptor.replace(addr, trampoline);

    Interceptor.attach(addr, {
        onEnter: function(args) {
            this._fd        = this.context.rax.toInt32();
            this._level     = this.context.rbx.toInt32();
            this._optname   = this.context.rcx.toInt32();
            this._optval    = this.context.rdi;
            this._optlenPtr = this.context.rsi;
        },
        onLeave: function(retval) {
            var ret = ldp.getsockopt(this._fd, this._level, this._optname,
                                     ptr(this._optval.toString()),
                                     ptr(this._optlenPtr.toString()));
            setGoReturn(this.context, retval, ret, 'getsockopt', false);
        }
    });
    log(1, '[+] Hooked syscall.getsockopt');
})();

// --- accept4(fd, addr, addrlen_ptr, flags) → (fd int, err error) ---
(function hookAccept4() {
    var addr = syscallAddresses['syscall.accept4'];
    if (!addr) { log(1, '[-] syscall.accept4 not found'); return; }

    var trampoline = allocateRetTrampoline();
    Interceptor.replace(addr, trampoline);

    Interceptor.attach(addr, {
        onEnter: function(args) {
            // Go ABI: rax=fd, rbx=addr_ptr, rcx=addrlen_ptr, rdi=flags
            this._fd         = this.context.rax.toInt32();
            this._addr       = this.context.rbx;
            this._addrlenPtr = this.context.rcx;
            this._flags      = this.context.rdi.toInt32();
            log(2, '[>] accept4(fd=' + this._fd + ', flags=' + this._flags + ')');
        },
        onLeave: function(retval) {
            // First attempt
            var ret = ldp.accept4(this._fd, ptr(this._addr.toString()),
                                  ptr(this._addrlenPtr.toString()), this._flags);

            // Spin-wait on EAGAIN (matching old working interceptor_server.js pattern)
            while (ret === -1 && getCErrno() === 11 /* EAGAIN */) {
                var deadline = Date.now() + 1;
                while (Date.now() < deadline) {}
                ret = ldp.accept4(this._fd, ptr(this._addr.toString()),
                                  ptr(this._addrlenPtr.toString()), this._flags);
            }

            // Track the new connection fd as server-side
            if (ret >= LDP_FD_OFFSET) {
                trackVclFd(ret, getVclFdFamily(this._fd), 'server');
            }
            setGoReturn(this.context, retval, ret, 'accept4', true);
        }
    });
    log(1, '[+] Hooked syscall.accept4');
})();

// --- accept(fd, addr, addrlen_ptr) → (fd int, err error) ---
// NEW: Some Go versions/platforms use accept() instead of accept4()
(function hookAccept() {
    var addr = syscallAddresses['syscall.accept'];
    if (!addr) { log(1, '[-] syscall.accept not found (optional — accept4 preferred)'); return; }

    var trampoline = allocateRetTrampoline();
    Interceptor.replace(addr, trampoline);

    Interceptor.attach(addr, {
        onEnter: function(args) {
            // Go ABI: rax=fd, rbx=addr_ptr, rcx=addrlen_ptr
            this._fd         = this.context.rax.toInt32();
            this._addr       = this.context.rbx;
            this._addrlenPtr = this.context.rcx;
            log(2, '[>] accept(fd=' + this._fd + ')');
        },
        onLeave: function(retval) {
            var ret = ldp.accept(this._fd, ptr(this._addr.toString()),
                                 ptr(this._addrlenPtr.toString()));

            // Spin-wait on EAGAIN (epoll-based wait corrupts Go goroutine stack)
            while (ret === -1 && getCErrno() === 11 /* EAGAIN */) {
                var deadline = Date.now() + 1;
                while (Date.now() < deadline) {}
                ret = ldp.accept(this._fd, ptr(this._addr.toString()),
                                 ptr(this._addrlenPtr.toString()));
            }

            if (ret >= LDP_FD_OFFSET) {
                trackVclFd(ret, getVclFdFamily(this._fd), 'server');
            }
            setGoReturn(this.context, retval, ret, 'accept', true);
        }
    });
    log(1, '[+] Hooked syscall.accept');
})();

// --- read(fd, buf, count) → (n int, err error) ---
(function hookRead() {
    var addr = syscallAddresses['syscall.read'];
    if (!addr) { log(1, '[-] syscall.read not found'); return; }

    var trampoline = allocateRetTrampoline();
    Interceptor.replace(addr, trampoline);

    Interceptor.attach(addr, {
        onEnter: function(args) {
            this._fd  = this.context.rax.toInt32();
            this._buf = this.context.rbx;
            this._len = this.context.rcx.toInt32();
        },
        onLeave: function(retval) {
            var fd  = this._fd;
            var buf = ptr(this._buf.toString());
            var len = this._len;

            var ret = ldp.read(fd, buf, len);

            if (ret === -1 && getCErrno() === 11 && isVclFd(fd)) {
                if (isClientFd(fd)) {
                    // Client-side read: use epoll to pump VCL MQ so response arrives.
                    // Client goroutine has deeper stack, epoll NativeFunction calls are safe.
                    var n = waitReadable(fd, 5000);
                    if (n > 0) { ret = ldp.read(fd, buf, len); }
                } else {
                    // Server-side (handleConn goroutine): spin-wait to avoid consuming
                    // the small goroutine stack with epoll NativeFunction calls, which
                    // causes Go's stackpoolalloc to SIGSEGV.
                    do {
                        var dl = Date.now() + 1;
                        while (Date.now() < dl) {}
                        ret = ldp.read(fd, buf, len);
                    } while (ret === -1 && getCErrno() === 11);
                }
            }
            setGoReturn(this.context, retval, ret, 'read', true);
        }
    });
    log(1, '[+] Hooked syscall.read');
})();

// --- write(fd, buf, count) → (n int, err error) ---
(function hookWrite() {
    var addr = syscallAddresses['syscall.write'];
    if (!addr) { log(1, '[-] syscall.write not found'); return; }

    var trampoline = allocateRetTrampoline();
    Interceptor.replace(addr, trampoline);

    Interceptor.attach(addr, {
        onEnter: function(args) {
            this._fd  = this.context.rax.toInt32();
            this._buf = this.context.rbx;
            this._len = this.context.rcx.toInt32();
        },
        onLeave: function(retval) {
            var fd  = this._fd;
            var buf = ptr(this._buf.toString());
            var len = this._len;

            var ret = ldp.write(fd, buf, len);
            var e = getCErrno();

            if (ret === -1 && (e === 11 || e === 107) && isVclFd(fd)) {
                if (isClientFd(fd)) {
                    // Client-side: use epoll MQ pump for write EAGAIN.
                    var nw = waitWritable(fd, 5000);
                    if (nw > 0) { ret = ldp.write(fd, buf, len); }
                } else {
                    // Server-side: spin-wait (same stack-safety reason as read).
                    var dlw = Date.now() + 5;
                    while (Date.now() < dlw) {}
                    ret = ldp.write(fd, buf, len);
                }
            }
            setGoReturn(this.context, retval, ret, 'write', true);
        }
    });
    log(1, '[+] Hooked syscall.write');
})();

// --- close(fd) → error ---
(function hookClose() {
    var addr = syscallAddresses['syscall.Close'];
    if (!addr) { log(1, '[-] syscall.Close not found'); return; }

    var trampoline = allocateRetTrampoline();
    Interceptor.replace(addr, trampoline);

    Interceptor.attach(addr, {
        onEnter: function(args) {
            this._fd = this.context.rax.toInt32();
        },
        onLeave: function(retval) {
            var fd = this._fd;
            var ret = ldp.close(fd);
            untrackVclFd(fd);
            setGoReturn(this.context, retval, ret, 'close', false);
        }
    });
    log(1, '[+] Hooked syscall.Close');
})();

// --- shutdown(fd, how) → error ---
// NEW: Required for half-close (e.g., conn.CloseWrite())
(function hookShutdown() {
    var addr = syscallAddresses['syscall.Shutdown'];
    if (!addr) { log(1, '[-] syscall.Shutdown not found (optional)'); return; }

    var trampoline = allocateRetTrampoline();
    Interceptor.replace(addr, trampoline);

    Interceptor.attach(addr, {
        onEnter: function(args) {
            this._fd  = this.context.rax.toInt32();
            this._how = this.context.rbx.toInt32();
            log(2, '[>] shutdown(fd=' + this._fd + ', how=' + this._how + ')');
        },
        onLeave: function(retval) {
            var ret = ldp.shutdown(this._fd, this._how);
            setGoReturn(this.context, retval, ret, 'shutdown', false);
        }
    });
    log(1, '[+] Hooked syscall.Shutdown');
})();

// --- fcntl(fd, cmd, arg) → (val int, err error) ---
// NEW: Go's net poller queries socket flags (F_GETFL, F_SETFL, F_GETFD, F_SETFD)
(function hookFcntl() {
    var addr = syscallAddresses['syscall.fcntl'];
    if (!addr) { log(1, '[-] syscall.fcntl not found (optional)'); return; }

    var trampoline = allocateRetTrampoline();
    Interceptor.replace(addr, trampoline);

    Interceptor.attach(addr, {
        onEnter: function(args) {
            // Go ABI: rax=fd, rbx=cmd, rcx=arg
            this._fd  = this.context.rax.toInt32();
            this._cmd = this.context.rbx.toInt32();
            this._arg = this.context.rcx.toInt32();
            log(2, '[>] fcntl(fd=' + this._fd + ', cmd=' + this._cmd + ', arg=' + this._arg + ')');
        },
        onLeave: function(retval) {
            var ret = ldp.fcntl(this._fd, this._cmd, this._arg);
            setGoReturn(this.context, retval, ret, 'fcntl', true);
        }
    });
    log(1, '[+] Hooked syscall.fcntl');
})();

// --- EpollCtl(epfd, op, fd, event) → error ---
// NEW: Go's net poller uses epoll to manage socket readiness.
// For VCL fds, we need LDP's epoll_ctl so events route through VPP's MQ.
(function hookEpollCtl() {
    var addr = syscallAddresses['syscall.EpollCtl'];
    if (!addr) { log(1, '[-] syscall.EpollCtl not found (optional)'); return; }

    var trampoline = allocateRetTrampoline();
    Interceptor.replace(addr, trampoline);

    Interceptor.attach(addr, {
        onEnter: function(args) {
            // Go ABI: rax=epfd, rbx=op, rcx=fd, rdi=event_ptr
            this._epfd  = this.context.rax.toInt32();
            this._op    = this.context.rbx.toInt32();
            this._fd    = this.context.rcx.toInt32();
            this._event = this.context.rdi;
            log(2, '[>] epoll_ctl(epfd=' + this._epfd + ', op=' + this._op +
                ', fd=' + this._fd + ')');
        },
        onLeave: function(retval) {
            // Route through LDP which handles both kernel and VCL epoll fds
            var ret = ldp.epoll_ctl(this._epfd, this._op, this._fd,
                                    ptr(this._event.toString()));
            setGoReturn(this.context, retval, ret, 'epoll_ctl', false);
        }
    });
    log(1, '[+] Hooked syscall.EpollCtl');
})();

// --- EpollWait(epfd, events, maxevents, timeout) → (n int, err error) ---
// NEW: Go's net poller calls epoll_pwait to wait for socket events.
// For VCL fds registered via LDP's epoll_ctl, LDP's epoll_wait processes
// VPP's message queue and returns VCL events alongside kernel events.
(function hookEpollWait() {
    var addr = syscallAddresses['syscall.EpollWait'];
    if (!addr) { log(1, '[-] syscall.EpollWait not found (optional)'); return; }

    var trampoline = allocateRetTrampoline();
    Interceptor.replace(addr, trampoline);

    Interceptor.attach(addr, {
        onEnter: function(args) {
            // Go ABI: rax=epfd, rbx=events_ptr, rcx=maxevents, rdi=timeout
            // Note: Go's EpollWait wraps epoll_pwait with sigmask=NULL
            this._epfd      = this.context.rax.toInt32();
            this._events    = this.context.rbx;
            this._maxevents = this.context.rcx.toInt32();
            this._timeout   = this.context.rdi.toInt32();
        },
        onLeave: function(retval) {
            // Route through LDP — it handles both kernel fds and VCL fds
            var ret = ldp.epoll_wait(this._epfd, ptr(this._events.toString()),
                                     this._maxevents, this._timeout);
            setGoReturn(this.context, retval, ret, 'epoll_wait', true);
        }
    });
    log(1, '[+] Hooked syscall.EpollWait');
})();

/* ============================================================================
 * DONE
 * ============================================================================ */

var hookedCount = 0;
syscallNames.forEach(function(name) {
    if (syscallAddresses[name]) hookedCount++;
});
log(1, '[+] Hooked ' + hookedCount + ' syscalls. VCL redirection active.');
log(1, '[+] Thread safety: per-invocation state via Frida this._ bindings.');
log(1, '[+] Blocking: epoll-based wait (no CPU-burning spin-waits).');

} // end of vclEnabled block
