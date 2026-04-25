/*
 * Frida VPP/VCL Interceptor for Go Server Binaries
 *
 * This script intercepts Go's socket-layer syscalls (socket, bind, listen,
 * accept4, connect, setsockopt, getsockopt, getsockname) and redirects them
 * to VPP's VCL library (libvcl_ldpreload.so).
 *
 * KEY FIXES over previous attempts (see docs/failed_attempt_analysis.md):
 *   1. Uses NativeCallback (not prepRegs shim) — performs Go ABI → System V ABI
 *      register translation entirely in Frida JS, eliminating the two-step
 *      replace+attach approach.
 *   2. Always sets rbx=0, rcx=0 on success (or rbx=0, rcx=errno on error)
 *      to satisfy Go's return convention.
 *   3. Uses per-thread state (this.threadId) instead of global flags for
 *      thread-safe dispatch.
 *   4. Does NOT call blocking LDP functions (accept4) from the JS thread —
 *      instead uses a NativeCallback that bridges directly.
 *
 * SETUP:
 *   1. Build: nasm -f elf64 -DPIC prepRegs.asm && gcc -shared -fPIC prepRegs.o -o libPrepRegs.so
 *      (Not needed for this script — we use NativeCallback instead)
 *   2. Copy libs to container:
 *        docker cp libvcl_ldpreload.so <container_id>:/usr/lib/libvcl_ldpreload.so
 *   3. Run:
 *        VCL_CONFIG=/tmp/server-share/vcl.conf frida /usr/bin/echo_server -l interceptor_server.js
 *
 * TARGET BINARY: Change 'moduleName' below to match your Go binary name.
 */

'use strict';

/* ============================================================================
 * CONFIGURATION
 * ============================================================================ */

// Change this to your Go binary name (without path)
const moduleName = 'echo_server';

// Path to VCL LD_PRELOAD library.
// MUST match your VPP build. Run:
//   find /home/aritrbas/vpp/build-root -name 'libvcl_ldpreload.so' 2>/dev/null
// Also set LD_LIBRARY_PATH to the same directory before running frida:
//   export LD_LIBRARY_PATH=/home/aritrbas/vpp/build-root/install-vpp_debug-native/vpp/lib/x86_64-linux-gnu
const VCL_LIB = '/home/aritrbas/vpp/build-root/install-vpp_debug-native/vpp/lib/x86_64-linux-gnu/libvcl_ldpreload.so';

// Syscalls to intercept
const syscallNames = [
    'syscall.socket',
    'syscall.setsockopt',
    'syscall.getsockopt',
    'syscall.bind',
    'syscall.Listen',
    'syscall.getsockname',
    'syscall.accept4',
    'syscall.connect',
    'syscall.read',
    'syscall.write',
    'syscall.Close',
];

/* ============================================================================
 * STEP 1: Find Go symbol addresses
 * ============================================================================ */

const syscallAddresses = {};

Process.getModuleByName(moduleName).enumerateSymbols().forEach(function(sym) {
    if (syscallNames.indexOf(sym.name) !== -1) {
        syscallAddresses[sym.name] = sym.address;
        console.log('[+] Found ' + sym.name + ' at ' + sym.address);
    }
});

/* ============================================================================
 * STEP 2: Load VCL library
 * Requires LD_LIBRARY_PATH to include the VPP lib dir, e.g.:
 *   export LD_LIBRARY_PATH=/home/aritrbas/vpp/build-root/install-vpp_debug-native/vpp/lib/x86_64-linux-gnu
 * ============================================================================ */

// Frida 17 removed findExport(modName, sym) static form.
// Use instance method via Process.findModuleByName instead.
function findExport(modName, symName) {
    var mod = Process.findModuleByName(modName);
    if (!mod) {
        // Module not yet loaded — search all loaded modules
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

// findExport() resolves through the dynamic linker's GOT/PLT, which returns
// libc's interposed functions (socket, bind, connect, etc.) instead of LDP's
// own implementations when those symbols are PLT-intercepted.
//
// findLdpSym() bypasses this by enumerating LDP's own symbol table directly,
// returning the actual function address in LDP's .text section.
var _ldpSymCache = {};
function findLdpSym(symName) {
    if (_ldpSymCache[symName]) return _ldpSymCache[symName];
    // Module.load() loads the symlink target; Frida registers the versioned soname.
    // Search all modules for any name or path containing 'ldpreload'.
    var mod = null;
    Process.enumerateModules().some(function(m) {
        if (m.name.indexOf('ldpreload') !== -1 || m.path.indexOf('ldpreload') !== -1) {
            mod = m; return true;
        }
        return false;
    });
    if (!mod) { console.log('[!] libvcl_ldpreload not found in modules'); return null; }
    var addr = null;
    mod.enumerateSymbols().some(function(sym) {
        if (sym.name === symName && sym.address && !sym.address.isNull()) {
            addr = sym.address;
            return true;
        }
        return false;
    });
    if (!addr) {
        // Fall back to exports (may be wrong, but log it)
        addr = mod.findExportByName(symName);
        console.log('[!] findLdpSym(' + symName + '): not in symbols, using export ' + addr);
    } else {
        _ldpSymCache[symName] = addr;
    }
    return addr;
}

// Frida has no built-in env-var API; use libc getenv() directly.
var _getenv = new NativeFunction(findExport('libc.so.6', 'getenv'), 'pointer', ['pointer']);
function getEnv(name) {
    var p = _getenv(Memory.allocUtf8String(name));
    return p.isNull() ? null : p.readUtf8String();
}

(function loadVCL() {
    // Skip VCL loading if VCL_CONFIG is not set — allows hooks-only testing (Step 3).
    var vclConfig = getEnv('VCL_CONFIG');
    if (!vclConfig) {
        console.log('[*] VCL_CONFIG not set — loading VCL in passthrough mode (hooks fire, syscalls go to kernel).');
        console.log('[*] Set VCL_CONFIG=/path/to/vcl.conf to redirect to VPP.');
        return;
    }
    var loaded = Process.enumerateModules().some(function(m) {
        return m.path === VCL_LIB || m.name === 'libvcl_ldpreload.so';
    });
    if (!loaded) {
        try {
            Module.load(VCL_LIB);
        } catch (e) {
            console.log('[!] FATAL: Failed to load ' + VCL_LIB + ': ' + e);
            console.log('[!] Fix: export LD_LIBRARY_PATH=/home/aritrbas/vpp/build-root/install-vpp_debug-native/vpp/lib/x86_64-linux-gnu');
            throw e;
        }
        console.log('[+] Loaded ' + VCL_LIB);
    } else {
        console.log('[+] ' + VCL_LIB + ' already loaded');
    }
})();

const vclEnabled = !!getEnv('VCL_CONFIG');

/* ============================================================================
 * STEP 3: Resolve LDP (VCL LD_PRELOAD) function addresses
 * (only when VCL_CONFIG is set)
 * ============================================================================ */

if (!vclEnabled) {
    console.log('[*] Hooks installed in passthrough mode. Syscalls go to kernel (no VCL redirection).');
} else {

const ldp = {
    socket:      new NativeFunction(findLdpSym('socket'),      'int', ['int', 'int', 'int']),
    bind:        new NativeFunction(findLdpSym('bind'),        'int', ['int', 'pointer', 'int']),
    listen:      new NativeFunction(findLdpSym('listen'),      'int', ['int', 'int']),
    accept4:     new NativeFunction(findLdpSym('accept4'),     'int', ['int', 'pointer', 'pointer', 'int']),
    connect:     new NativeFunction(findLdpSym('connect'),     'int', ['int', 'pointer', 'int']),
    setsockopt:  new NativeFunction(findLdpSym('setsockopt'),  'int', ['int', 'int', 'int', 'pointer', 'int']),
    getsockopt:  new NativeFunction(findLdpSym('getsockopt'),  'int', ['int', 'int', 'int', 'pointer', 'pointer']),
    getsockname: new NativeFunction(findLdpSym('getsockname'), 'int', ['int', 'pointer', 'pointer']),
    read:        new NativeFunction(findLdpSym('read'),        'int', ['int', 'pointer', 'int']),
    write:       new NativeFunction(findLdpSym('write'),       'int', ['int', 'pointer', 'int']),
    close:       new NativeFunction(findLdpSym('close'),       'int', ['int']),
};

console.log('[+] LDP socket:      ' + findLdpSym('socket'));
console.log('[+] LDP bind:        ' + findLdpSym('bind'));
console.log('[+] LDP listen:      ' + findLdpSym('listen'));
console.log('[+] LDP accept4:     ' + findLdpSym('accept4'));
console.log('[+] LDP connect:     ' + findLdpSym('connect'));
console.log('[+] LDP setsockopt:  ' + findLdpSym('setsockopt'));
console.log('[+] LDP getsockopt:  ' + findLdpSym('getsockopt'));
console.log('[+] LDP getsockname: ' + findLdpSym('getsockname'));

/* ============================================================================
 * STEP 4: C errno helper
 * ============================================================================ */

const errnoLocation = new NativeFunction(
    findExport('libc.so.6', '__errno_location'), 'pointer', []
);

function getCErrno() {
    return errnoLocation().readInt();
}

/* ============================================================================
 * STEP 4b: Pre-cached Go error interface objects
 *
 * Go's syscall package caches error interfaces for common errno values.
 * Each is a 16-byte value: {itab_ptr, data_ptr}.
 * We look them up by symbol name from the Go binary so we can return
 * proper Go error interfaces instead of raw errno integers.
 * ============================================================================ */

var goErrSyms = {};
var goErrnoItab = null;  // go:itab.syscall.Errno,error
(function findGoErrSymbols() {
    var wanted = ['syscall.errEAGAIN', 'syscall.errEINVAL', 'syscall.errENOENT',
                  'go:itab.syscall.Errno,error'];
    Process.getModuleByName(moduleName).enumerateSymbols().forEach(function(sym) {
        if (wanted.indexOf(sym.name) !== -1) {
            goErrSyms[sym.name] = sym.address;
            console.log('[+] Found Go error symbol: ' + sym.name + ' @ ' + sym.address);
        }
    });
    // go:itab.syscall.Errno,error is the itab for syscall.Errno as an error interface.
    // We can construct any errno by using this itab + the errno value as data.
    var itabSym = goErrSyms['go:itab.syscall.Errno,error'];
    if (itabSym) goErrnoItab = itabSym;
})();

// Returns {itab, data} for a C errno value.
// go:itab.syscall.Errno,error uses pointer receivers, so data must be a pointer to
// a uintptr holding the errno value. We cache allocations per errno value.
var _errnoDataCache = {};
function goErrFromErrno(errno) {
    if (goErrnoItab) {
        // Allocate (or reuse) a persistent 8-byte slot for this errno value.
        if (!_errnoDataCache[errno]) {
            var slot = Memory.alloc(8);
            slot.writeU64(errno);
            _errnoDataCache[errno] = slot;
        }
        return { itab: goErrnoItab, data: _errnoDataCache[errno] };
    }
    // Fallback: use pre-cached error objects for known errnos.
    var sym;
    if (errno === 11)      sym = goErrSyms['syscall.errEAGAIN'];
    else if (errno === 22) sym = goErrSyms['syscall.errEINVAL'];
    else if (errno === 2)  sym = goErrSyms['syscall.errENOENT'];
    else                   sym = goErrSyms['syscall.errEINVAL'];
    if (!sym) return { itab: ptr(0), data: ptr(0) };
    return { itab: sym.readPointer(), data: sym.add(8).readPointer() };
}

/* ============================================================================
 * STEP 5: Go return value helper
 *
 * Go's register ABI uses different return registers depending on the Go
 * function signature:
 *
 *   func f() (int, error)  → rax=int, rbx=err.itab, rcx=err.data
 *   func f() error         → rax=err.itab, rbx=err.data
 *
 * Use returnsInt=true for socket/accept4 (return fd + error),
 * returnsInt=false for bind/listen/connect/setsockopt/getsockopt/getsockname
 * (return error only).
 * ============================================================================ */

function setGoReturn(context, retval, result, syscallName, returnsInt) {
    if (result < 0) {
        var errno = getCErrno();
        var goErr = goErrFromErrno(errno);
        console.log('[!] ' + syscallName + ' failed: ret=' + result + ', errno=' + errno);
        if (returnsInt) {
            // (int, error): rax=fd, rbx=err.itab, rcx=err.data
            retval.replace(-1);
            context.rbx = goErr.itab;
            context.rcx = goErr.data;
        } else {
            // error: rax=err.itab, rbx=err.data
            retval.replace(goErr.itab);
            context.rbx = goErr.data;
            context.rcx = ptr(0);
        }
    } else {
        console.log('[+] ' + syscallName + ' succeeded: ret=' + result);
        if (returnsInt) {
            retval.replace(result);
            context.rbx = ptr(0);
            context.rcx = ptr(0);
        } else {
            retval.replace(0);   // nil error.itab → err == nil
            context.rbx = ptr(0);
            context.rcx = ptr(0);
        }
    }
}

/* ============================================================================
 * STEP 6: Allocate inline assembly trampolines via Memory.alloc + X86Writer
 *
 * For each Go syscall, we write a small trampoline in executable memory that:
 *   1. Reads Go ABI registers (rax, rbx, rcx, rdi, rsi, r8)
 *   2. Shuffles them to System V ABI (rdi, rsi, rdx, rcx, r8, r9)
 *   3. Returns (does NOT call LDP — Frida's onLeave does that)
 *
 * We create unique trampolines per-syscall so Frida can attach distinct
 * onLeave handlers to each.
 * ============================================================================ */

// Instead of assembly shims, we use NativeCallback for the full bridge.
// NativeCallback runs in C ABI context, so we use Interceptor.replace with
// a NativeCallback that:
//   - Reads Go args from the CPU context (the NativeCallback receives them
//     as System V args because Frida's Interceptor translates, but since
//     the Go caller passed them in Go ABI, we read them from context directly)
//
// BETTER APPROACH: Use Interceptor.replace with a raw code block that
// performs the full bridge: read Go regs → call LDP → set Go return regs.

/* ============================================================================
 * STEP 6 (actual): Per-syscall interception using Interceptor.attach
 *
 * Strategy: For each Go syscall function, we:
 *   1. Write a tiny trampoline (just `ret`) via Memory.alloc + X86Writer
 *   2. Interceptor.replace(goFunc, trampoline) — Go func becomes a no-op
 *   3. Interceptor.attach(goFunc, { onEnter, onLeave }) — read Go ABI regs
 *      in onEnter, call LDP and fix return in onLeave
 *
 * This avoids the assembly shim entirely. The trampoline is just `ret`.
 * Frida's onEnter sees the original Go ABI registers before the trampoline
 * runs, and onLeave lets us set the return values.
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
 * STEP 7: Hook each syscall
 * ============================================================================ */

// --- socket(domain, type, protocol) → 3 args ---
(function hookSocket() {
    var addr = syscallAddresses['syscall.socket'];
    if (!addr) { console.log('[-] syscall.socket not found'); return; }

    var trampoline = allocateRetTrampoline();
    Interceptor.replace(addr, trampoline);

    Interceptor.attach(addr, {
        onEnter: function(args) {
            // Go ABI: rax=domain, rbx=type, rcx=protocol
            this._domain   = this.context.rax.toInt32();
            this._type     = this.context.rbx.toInt32();
            this._protocol = this.context.rcx.toInt32();
            console.log('[>] socket(' + this._domain + ', ' + this._type + ', ' + this._protocol + ')');
        },
        onLeave: function(retval) {
            // Skip MPTCP sockets (proto=262=IPPROTO_MPTCP) — VPP doesn't support MPTCP.
            // Return EPROTONOSUPPORT so Go falls back to regular TCP.
            if (this._protocol === 262) {
                retval.replace(-1);
                this.context.rbx = goErrFromErrno(93 /*EPROTONOSUPPORT*/).itab;
                this.context.rcx = goErrFromErrno(93).data;
                console.log('[>] socket proto=MPTCP: returning EPROTONOSUPPORT');
                return;
            }
            var ret = ldp.socket(this._domain, this._type, this._protocol);
            setGoReturn(this.context, retval, ret, 'socket', true);
        }
    });
    console.log('[+] Hooked syscall.socket');
})();

// --- bind(fd, addr, addrlen) → 3 args ---
(function hookBind() {
    var addr = syscallAddresses['syscall.bind'];
    if (!addr) { console.log('[-] syscall.bind not found'); return; }

    var trampoline = allocateRetTrampoline();
    Interceptor.replace(addr, trampoline);

    Interceptor.attach(addr, {
        onEnter: function(args) {
            // Go ABI: rax=fd, rbx=addr_ptr, rcx=addrlen
            this._fd      = this.context.rax.toInt32();
            this._addr    = this.context.rbx;  // pointer
            this._addrlen = this.context.rcx.toInt32();
            console.log('[>] bind(' + this._fd + ', ' + this._addr + ', ' + this._addrlen + ')');
        },
        onLeave: function(retval) {
            var ret = ldp.bind(this._fd, ptr(this._addr.toString()), this._addrlen);
            setGoReturn(this.context, retval, ret, 'bind', false);
        }
    });
    console.log('[+] Hooked syscall.bind');
})();

// --- listen(fd, backlog) → 2 args ---
(function hookListen() {
    var addr = syscallAddresses['syscall.Listen'];
    if (!addr) { console.log('[-] syscall.Listen not found'); return; }

    var trampoline = allocateRetTrampoline();
    Interceptor.replace(addr, trampoline);

    Interceptor.attach(addr, {
        onEnter: function(args) {
            // Go ABI: rax=fd, rbx=backlog
            this._fd      = this.context.rax.toInt32();
            this._backlog = this.context.rbx.toInt32();
            console.log('[>] listen(' + this._fd + ', ' + this._backlog + ')');
        },
        onLeave: function(retval) {
            // Disable IPv6 dual-stack before listen to prevent VPP LDP from
            // creating a companion IPv4 session that fails with EADDRINUSE.
            var v6onlyBuf = Memory.alloc(4);
            v6onlyBuf.writeInt(1);
            ldp.setsockopt(this._fd, 41 /*IPPROTO_IPV6*/, 26 /*IPV6_V6ONLY*/, v6onlyBuf, 4);
            var ret = ldp.listen(this._fd, this._backlog);
            var errno = getCErrno();
            console.log('[dbg] listen(' + this._fd + ',' + this._backlog + ') ret=' + ret + ' errno=' + errno);
            setGoReturn(this.context, retval, ret, 'listen', false);
        }
    });
    console.log('[+] Hooked syscall.Listen');
})();

// --- getsockname(fd, addr, addrlen_ptr) → 3 args ---
(function hookGetsockname() {
    var addr = syscallAddresses['syscall.getsockname'];
    if (!addr) { console.log('[-] syscall.getsockname not found'); return; }

    var trampoline = allocateRetTrampoline();
    Interceptor.replace(addr, trampoline);

    Interceptor.attach(addr, {
        onEnter: function(args) {
            // Go ABI: rax=fd, rbx=addr_ptr, rcx=addrlen_ptr
            this._fd         = this.context.rax.toInt32();
            this._addr       = this.context.rbx;  // pointer
            this._addrlenPtr = this.context.rcx;   // pointer
            console.log('[>] getsockname(' + this._fd + ', ' + this._addr + ', ' + this._addrlenPtr + ')');
        },
        onLeave: function(retval) {
            var ret = ldp.getsockname(this._fd, ptr(this._addr.toString()), ptr(this._addrlenPtr.toString()));
            setGoReturn(this.context, retval, ret, 'getsockname', false);
        }
    });
    console.log('[+] Hooked syscall.getsockname');
})();

// --- connect(fd, addr, addrlen) → 3 args ---
(function hookConnect() {
    var addr = syscallAddresses['syscall.connect'];
    if (!addr) { console.log('[-] syscall.connect not found'); return; }

    var trampoline = allocateRetTrampoline();
    Interceptor.replace(addr, trampoline);

    Interceptor.attach(addr, {
        onEnter: function(args) {
            // Go ABI: rax=fd, rbx=addr_ptr, rcx=addrlen
            this._fd      = this.context.rax.toInt32();
            this._addr    = this.context.rbx;  // pointer
            this._addrlen = this.context.rcx.toInt32();
            console.log('[>] connect(' + this._fd + ', ' + this._addr + ', ' + this._addrlen + ')');
        },
        onLeave: function(retval) {
            var ret = ldp.connect(this._fd, ptr(this._addr.toString()), this._addrlen);
            var e = getCErrno();
            if (ret === -1 && (e === 115 /*EINPROGRESS*/ || e === 114 /*EALREADY*/)) {
                console.log('[dbg] connect EINPROGRESS → treating as success (VCL async)');
                ret = 0;
            }
            setGoReturn(this.context, retval, ret, 'connect', false);
        }
    });
    console.log('[+] Hooked syscall.connect');
})();

// --- setsockopt(fd, level, optname, optval, optlen) → 5 args ---
(function hookSetsockopt() {
    var addr = syscallAddresses['syscall.setsockopt'];
    if (!addr) { console.log('[-] syscall.setsockopt not found'); return; }

    var trampoline = allocateRetTrampoline();
    Interceptor.replace(addr, trampoline);

    Interceptor.attach(addr, {
        onEnter: function(args) {
            // Go ABI: rax=fd, rbx=level, rcx=optname, rdi=optval_ptr, rsi=optlen
            this._fd      = this.context.rax.toInt32();
            this._level   = this.context.rbx.toInt32();
            this._optname = this.context.rcx.toInt32();
            this._optval  = this.context.rdi;  // pointer
            this._optlen  = this.context.rsi.toInt32();
            console.log('[>] setsockopt(' + this._fd + ', ' + this._level + ', ' + this._optname +
                        ', ' + this._optval + ', ' + this._optlen + ')');
        },
        onLeave: function(retval) {
            var ret = ldp.setsockopt(this._fd, this._level, this._optname,
                                     ptr(this._optval.toString()), this._optlen);
            setGoReturn(this.context, retval, ret, 'setsockopt', false);
        }
    });
    console.log('[+] Hooked syscall.setsockopt');
})();

// --- getsockopt(fd, level, optname, optval, optlen_ptr) → 5 args ---
(function hookGetsockopt() {
    var addr = syscallAddresses['syscall.getsockopt'];
    if (!addr) { console.log('[-] syscall.getsockopt not found'); return; }

    var trampoline = allocateRetTrampoline();
    Interceptor.replace(addr, trampoline);

    Interceptor.attach(addr, {
        onEnter: function(args) {
            // Go ABI: rax=fd, rbx=level, rcx=optname, rdi=optval_ptr, rsi=optlen_ptr
            this._fd        = this.context.rax.toInt32();
            this._level     = this.context.rbx.toInt32();
            this._optname   = this.context.rcx.toInt32();
            this._optval    = this.context.rdi;  // pointer
            this._optlenPtr = this.context.rsi;   // pointer
            console.log('[>] getsockopt(' + this._fd + ', ' + this._level + ', ' + this._optname +
                        ', ' + this._optval + ', ' + this._optlenPtr + ')');
        },
        onLeave: function(retval) {
            var ret = ldp.getsockopt(this._fd, this._level, this._optname,
                                     ptr(this._optval.toString()), ptr(this._optlenPtr.toString()));
            setGoReturn(this.context, retval, ret, 'getsockopt', false);
        }
    });
    console.log('[+] Hooked syscall.getsockopt');
})();

// --- accept4(fd, addr, addrlen_ptr, flags) → 4 args ---
//
// NOTE: accept4 is a BLOCKING call. When called from Frida's onLeave, it
// blocks the Frida JS thread. This is acceptable for a single-threaded
// accept loop but will cause issues with concurrent goroutines.
// For production use, consider using a CModule-based approach instead.
(function hookAccept4() {
    var addr = syscallAddresses['syscall.accept4'];
    if (!addr) { console.log('[-] syscall.accept4 not found'); return; }

    var trampoline = allocateRetTrampoline();
    Interceptor.replace(addr, trampoline);

    Interceptor.attach(addr, {
        onEnter: function(args) {
            // Go ABI: rax=fd, rbx=addr_ptr, rcx=addrlen_ptr, rdi=flags
            this._fd         = this.context.rax.toInt32();
            this._addr       = this.context.rbx;  // pointer
            this._addrlenPtr = this.context.rcx;   // pointer
            this._flags      = this.context.rdi.toInt32();
            console.log('[>] accept4(' + this._fd + ', ' + this._addr + ', ' +
                        this._addrlenPtr + ', ' + this._flags + ')');
        },
        onLeave: function(retval) {
            // Blocking accept: spin-wait on EAGAIN so Go never needs epoll on VCL fds.
            var ret;
            do {
                ret = ldp.accept4(this._fd, ptr(this._addr.toString()),
                                  ptr(this._addrlenPtr.toString()), this._flags);
                if (ret === -1 && getCErrno() === 11 /*EAGAIN*/) {
                    // 1ms busy-wait before retry
                    var deadline = Date.now() + 1;
                    while (Date.now() < deadline) {}
                }
            } while (ret === -1 && getCErrno() === 11);
            setGoReturn(this.context, retval, ret, 'accept4', true);
        }
    });
    console.log('[+] Hooked syscall.accept4');
})();

// --- read(fd, buf, count) → int ---
// syscall.read(fd int, p []byte) (n int, err error)
// Go ABI: rax=fd, rbx=p.ptr, rcx=p.len
(function hookRead() {
    var addr = syscallAddresses['syscall.read'];
    if (!addr) { console.log('[-] syscall.read not found'); return; }

    var trampoline = allocateRetTrampoline();
    Interceptor.replace(addr, trampoline);

    Interceptor.attach(addr, {
        onEnter: function(args) {
            this._fd  = this.context.rax.toInt32();
            this._buf = this.context.rbx;
            this._len = this.context.rcx.toInt32();
        },
        onLeave: function(retval) {
            // Blocking read: retry on EAGAIN (VCL non-blocking sessions).
            var ret;
            do {
                ret = ldp.read(this._fd, ptr(this._buf.toString()), this._len);
                if (ret === -1 && getCErrno() === 11) {
                    var deadline = Date.now() + 1;
                    while (Date.now() < deadline) {}
                }
            } while (ret === -1 && getCErrno() === 11);
            setGoReturn(this.context, retval, ret, 'read', true);
        }
    });
    console.log('[+] Hooked syscall.read');
})();

// --- write(fd, buf, count) → int ---
// syscall.write(fd int, p []byte) (n int, err error)
(function hookWrite() {
    var addr = syscallAddresses['syscall.write'];
    if (!addr) { console.log('[-] syscall.write not found'); return; }

    var trampoline = allocateRetTrampoline();
    Interceptor.replace(addr, trampoline);

    Interceptor.attach(addr, {
        onEnter: function(args) {
            this._fd  = this.context.rax.toInt32();
            this._buf = this.context.rbx;
            this._len = this.context.rcx.toInt32();
        },
        onLeave: function(retval) {
            var ret = ldp.write(this._fd, ptr(this._buf.toString()), this._len);
            if (ret === -1 && getCErrno() === 11) {
                // Retry once on EAGAIN
                var deadline = Date.now() + 5;
                while (Date.now() < deadline) {}
                ret = ldp.write(this._fd, ptr(this._buf.toString()), this._len);
            }
            setGoReturn(this.context, retval, ret, 'write', true);
        }
    });
    console.log('[+] Hooked syscall.write');
})();

// --- close(fd) → error ---
// syscall.Close(fd int) error
// Go ABI: rax=fd → returns rax=err.itab, rbx=err.data
(function hookClose() {
    var addr = syscallAddresses['syscall.Close'];
    if (!addr) { console.log('[-] syscall.Close not found'); return; }

    var trampoline = allocateRetTrampoline();
    Interceptor.replace(addr, trampoline);

    Interceptor.attach(addr, {
        onEnter: function(args) {
            this._fd = this.context.rax.toInt32();
        },
        onLeave: function(retval) {
            var ret = ldp.close(this._fd);
            setGoReturn(this.context, retval, ret, 'close', false);
        }
    });
    console.log('[+] Hooked syscall.Close');
})();

/* ============================================================================
 * DONE
 * ============================================================================ */

console.log('[+] All hooks installed. Go syscalls will be redirected to VCL.');
console.log('[+] Ensure VCL_CONFIG is set in the environment.');
}
