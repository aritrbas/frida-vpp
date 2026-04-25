/*
 * Frida VPP/VCL Interceptor for Go Client Binaries
 *
 * Same architecture as interceptor_server.js but targets client binaries.
 * Does NOT hook accept4 or listen (not needed for client).
 * Hooks: socket, connect, setsockopt, getsockopt, getsockname, bind.
 *
 * Run:
 *   VCL_CONFIG=/tmp/client-share/vcl.conf frida ./echo_client -l interceptor_client.js
 */

'use strict';

const moduleName = 'echo_client';

const syscallNames = [
    'syscall.socket',
    'syscall.setsockopt',
    'syscall.getsockopt',
    'syscall.bind',
    'syscall.getsockname',
    'syscall.connect'
];

/* Find Go symbol addresses */
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

/* Load VCL library */
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

/* Resolve LDP functions */
const ldp = {
    socket:      new NativeFunction(Module.findExportByName(VCL_LIB, 'socket'),      'int', ['int', 'int', 'int']),
    bind:        new NativeFunction(Module.findExportByName(VCL_LIB, 'bind'),        'int', ['int', 'pointer', 'int']),
    connect:     new NativeFunction(Module.findExportByName(VCL_LIB, 'connect'),     'int', ['int', 'pointer', 'int']),
    setsockopt:  new NativeFunction(Module.findExportByName(VCL_LIB, 'setsockopt'),  'int', ['int', 'int', 'int', 'pointer', 'int']),
    getsockopt:  new NativeFunction(Module.findExportByName(VCL_LIB, 'getsockopt'),  'int', ['int', 'int', 'int', 'pointer', 'pointer']),
    getsockname: new NativeFunction(Module.findExportByName(VCL_LIB, 'getsockname'), 'int', ['int', 'pointer', 'pointer']),
};

/* C errno helper */
const errnoLocation = new NativeFunction(
    Module.findExportByName(null, '__errno_location'), 'pointer', []
);
function getCErrno() { return errnoLocation().readInt(); }

/* Go return value helper */
function setGoReturn(context, retval, result, syscallName) {
    if (result < 0) {
        var errno = getCErrno();
        console.log('[!] ' + syscallName + ' failed: ret=' + result + ', errno=' + errno);
        retval.replace(-1);
        context.rbx = ptr(0);
        context.rcx = ptr(errno);
    } else {
        console.log('[+] ' + syscallName + ' succeeded: ret=' + result);
        retval.replace(result);
        context.rbx = ptr(0);
        context.rcx = ptr(0);
    }
}

function allocateRetTrampoline() {
    var block = Memory.alloc(Process.pageSize);
    Memory.patchCode(block, 16, function(code) {
        var w = new X86Writer(code, { pc: block });
        w.putRet();
        w.flush();
    });
    return block;
}

/* Hook socket */
(function hookSocket() {
    var addr = syscallAddresses['syscall.socket'];
    if (!addr) { console.log('[-] syscall.socket not found'); return; }
    var trampoline = allocateRetTrampoline();
    Interceptor.replace(addr, trampoline);
    Interceptor.attach(addr, {
        onEnter: function(args) {
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

/* Hook bind */
(function hookBind() {
    var addr = syscallAddresses['syscall.bind'];
    if (!addr) { console.log('[-] syscall.bind not found'); return; }
    var trampoline = allocateRetTrampoline();
    Interceptor.replace(addr, trampoline);
    Interceptor.attach(addr, {
        onEnter: function(args) {
            this._fd      = this.context.rax.toInt32();
            this._addr    = this.context.rbx;
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

/* Hook getsockname */
(function hookGetsockname() {
    var addr = syscallAddresses['syscall.getsockname'];
    if (!addr) { console.log('[-] syscall.getsockname not found'); return; }
    var trampoline = allocateRetTrampoline();
    Interceptor.replace(addr, trampoline);
    Interceptor.attach(addr, {
        onEnter: function(args) {
            this._fd         = this.context.rax.toInt32();
            this._addr       = this.context.rbx;
            this._addrlenPtr = this.context.rcx;
            console.log('[>] getsockname(' + this._fd + ', ' + this._addr + ', ' + this._addrlenPtr + ')');
        },
        onLeave: function(retval) {
            var ret = ldp.getsockname(this._fd, ptr(this._addr.toString()), ptr(this._addrlenPtr.toString()));
            setGoReturn(this.context, retval, ret, 'getsockname');
        }
    });
    console.log('[+] Hooked syscall.getsockname');
})();

/* Hook connect */
(function hookConnect() {
    var addr = syscallAddresses['syscall.connect'];
    if (!addr) { console.log('[-] syscall.connect not found'); return; }
    var trampoline = allocateRetTrampoline();
    Interceptor.replace(addr, trampoline);
    Interceptor.attach(addr, {
        onEnter: function(args) {
            this._fd      = this.context.rax.toInt32();
            this._addr    = this.context.rbx;
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

/* Hook setsockopt */
(function hookSetsockopt() {
    var addr = syscallAddresses['syscall.setsockopt'];
    if (!addr) { console.log('[-] syscall.setsockopt not found'); return; }
    var trampoline = allocateRetTrampoline();
    Interceptor.replace(addr, trampoline);
    Interceptor.attach(addr, {
        onEnter: function(args) {
            this._fd      = this.context.rax.toInt32();
            this._level   = this.context.rbx.toInt32();
            this._optname = this.context.rcx.toInt32();
            this._optval  = this.context.rdi;
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

/* Hook getsockopt */
(function hookGetsockopt() {
    var addr = syscallAddresses['syscall.getsockopt'];
    if (!addr) { console.log('[-] syscall.getsockopt not found'); return; }
    var trampoline = allocateRetTrampoline();
    Interceptor.replace(addr, trampoline);
    Interceptor.attach(addr, {
        onEnter: function(args) {
            this._fd        = this.context.rax.toInt32();
            this._level     = this.context.rbx.toInt32();
            this._optname   = this.context.rcx.toInt32();
            this._optval    = this.context.rdi;
            this._optlenPtr = this.context.rsi;
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

console.log('[+] All client hooks installed. Go syscalls will be redirected to VCL.');
