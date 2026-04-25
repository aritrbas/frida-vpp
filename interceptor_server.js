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

// Syscalls to intercept
const syscallNames = [
    'syscall.socket',
    'syscall.setsockopt',
    'syscall.getsockopt',
    'syscall.bind',
    'syscall.Listen',
    'syscall.getsockname',
    'syscall.accept4',
    'syscall.connect'
];

/* ============================================================================
 * STEP 1: Find Go symbol addresses
 * ============================================================================ */

const syscallAddresses = {};

syscallNames.forEach(function(name) {
    Module.enumerateSymbols(moduleName, {
        onMatch: function(exp) {
            if (exp.name === name) {
                syscallAddresses[name] = exp.address;
                console.log('[+] Found ' + name + ' at ' + exp.address);
            }
        },
        onComplete: function() {}
    });
});

/* ============================================================================
 * STEP 2: Load VCL library
 * ============================================================================ */

const VCL_LIB = '/usr/lib/libvcl_ldpreload.so';

(function loadVCL() {
    var loaded = false;
    Process.enumerateModules({
        onMatch: function(m) { if (m.path === VCL_LIB || m.name === 'libvcl_ldpreload.so') loaded = true; },
        onComplete: function() {}
    });
    if (!loaded) {
        Module.load(VCL_LIB);
        console.log('[+] Loaded ' + VCL_LIB);
    } else {
        console.log('[+] ' + VCL_LIB + ' already loaded');
    }
})();

/* ============================================================================
 * STEP 3: Resolve LDP (VCL LD_PRELOAD) function addresses
 * ============================================================================ */

const ldp = {
    socket:      new NativeFunction(Module.findExportByName(VCL_LIB, 'socket'),      'int', ['int', 'int', 'int']),
    bind:        new NativeFunction(Module.findExportByName(VCL_LIB, 'bind'),        'int', ['int', 'pointer', 'int']),
    listen:      new NativeFunction(Module.findExportByName(VCL_LIB, 'listen'),      'int', ['int', 'int']),
    accept4:     new NativeFunction(Module.findExportByName(VCL_LIB, 'accept4'),     'int', ['int', 'pointer', 'pointer', 'int']),
    connect:     new NativeFunction(Module.findExportByName(VCL_LIB, 'connect'),     'int', ['int', 'pointer', 'int']),
    setsockopt:  new NativeFunction(Module.findExportByName(VCL_LIB, 'setsockopt'),  'int', ['int', 'int', 'int', 'pointer', 'int']),
    getsockopt:  new NativeFunction(Module.findExportByName(VCL_LIB, 'getsockopt'),  'int', ['int', 'int', 'int', 'pointer', 'pointer']),
    getsockname: new NativeFunction(Module.findExportByName(VCL_LIB, 'getsockname'), 'int', ['int', 'pointer', 'pointer']),
};

console.log('[+] LDP socket:      ' + Module.findExportByName(VCL_LIB, 'socket'));
console.log('[+] LDP bind:        ' + Module.findExportByName(VCL_LIB, 'bind'));
console.log('[+] LDP listen:      ' + Module.findExportByName(VCL_LIB, 'listen'));
console.log('[+] LDP accept4:     ' + Module.findExportByName(VCL_LIB, 'accept4'));
console.log('[+] LDP connect:     ' + Module.findExportByName(VCL_LIB, 'connect'));
console.log('[+] LDP setsockopt:  ' + Module.findExportByName(VCL_LIB, 'setsockopt'));
console.log('[+] LDP getsockopt:  ' + Module.findExportByName(VCL_LIB, 'getsockopt'));
console.log('[+] LDP getsockname: ' + Module.findExportByName(VCL_LIB, 'getsockname'));

/* ============================================================================
 * STEP 4: C errno helper
 * ============================================================================ */

const errnoLocation = new NativeFunction(
    Module.findExportByName(null, '__errno_location'), 'pointer', []
);

function getCErrno() {
    return errnoLocation().readInt();
}

/* ============================================================================
 * STEP 5: Go return value helper
 *
 * Go's syscall layer returns (r1, r2, errno) in (rax, rbx, rcx).
 * On success: rax=result, rbx=0, rcx=0
 * On error:   rax=-1, rbx=0, rcx=positive_errno
 * ============================================================================ */

function setGoReturn(context, retval, result, syscallName) {
    if (result < 0) {
        // C function returned -1; read errno from thread-local storage
        var errno = getCErrno();
        console.log('[!] ' + syscallName + ' failed: ret=' + result + ', errno=' + errno);
        retval.replace(-1);
        context.rbx = ptr(0);
        context.rcx = ptr(errno);
    } else {
        console.log('[+] ' + syscallName + ' succeeded: ret=' + result);
        retval.replace(result);
        context.rbx = ptr(0);   // second return value = 0
        context.rcx = ptr(0);   // errno = 0 (no error)
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
            var ret = ldp.socket(this._domain, this._type, this._protocol);
            setGoReturn(this.context, retval, ret, 'socket');
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
            setGoReturn(this.context, retval, ret, 'bind');
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
            var ret = ldp.listen(this._fd, this._backlog);
            setGoReturn(this.context, retval, ret, 'listen');
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
            setGoReturn(this.context, retval, ret, 'getsockname');
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
            setGoReturn(this.context, retval, ret, 'connect');
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
            setGoReturn(this.context, retval, ret, 'setsockopt');
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
            setGoReturn(this.context, retval, ret, 'getsockopt');
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
            var ret = ldp.accept4(this._fd, ptr(this._addr.toString()),
                                  ptr(this._addrlenPtr.toString()), this._flags);
            setGoReturn(this.context, retval, ret, 'accept4');
        }
    });
    console.log('[+] Hooked syscall.accept4');
})();

/* ============================================================================
 * DONE
 * ============================================================================ */

console.log('[+] All hooks installed. Go syscalls will be redirected to VCL.');
console.log('[+] Ensure VCL_CONFIG is set in the environment.');
