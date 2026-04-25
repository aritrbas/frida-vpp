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

// Path to VCL LD_PRELOAD library.
// MUST match your VPP build. Run:
//   find /home/aritrbas/vpp/build-root -name 'libvcl_ldpreload.so' 2>/dev/null
// Also set LD_LIBRARY_PATH to the same directory before running frida:
//   export LD_LIBRARY_PATH=/home/aritrbas/vpp/build-root/install-vpp_debug-native/vpp/lib/x86_64-linux-gnu
const VCL_LIB = '/home/aritrbas/vpp/build-root/install-vpp_debug-native/vpp/lib/x86_64-linux-gnu/libvcl_ldpreload.so';

const syscallNames = [
    'syscall.socket',
    'syscall.setsockopt',
    'syscall.getsockopt',
    'syscall.bind',
    'syscall.getsockname',
    'syscall.connect',
    'syscall.read',
    'syscall.write',
    'syscall.Close',
];

/* Find Go symbol addresses */
const syscallAddresses = {};
Process.getModuleByName(moduleName).enumerateSymbols().forEach(function(sym) {
    if (syscallNames.indexOf(sym.name) !== -1) {
        syscallAddresses[sym.name] = sym.address;
        console.log('[+] Found ' + sym.name + ' at ' + sym.address);
    }
});

// Frida 17 removed findExport(modName, sym) static form.
// Use instance method via Process.findModuleByName instead.
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

/* Load VCL library.
 * Requires LD_LIBRARY_PATH to include the VPP lib dir, e.g.:
 *   export LD_LIBRARY_PATH=/home/aritrbas/vpp/build-root/install-vpp_debug-native/vpp/lib/x86_64-linux-gnu
 */
(function loadVCL() {
    var vclConfig = getEnv('VCL_CONFIG');
    if (!vclConfig) {
        console.log('[*] VCL_CONFIG not set — passthrough mode (hooks fire, syscalls go to kernel).');
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

/* Resolve LDP functions and install hooks (only when VCL_CONFIG is set) */
if (!vclEnabled) {
    console.log('[*] Hooks installed in passthrough mode. Syscalls go to kernel (no VCL redirection).');
} else {
const ldp = {
    socket:        new NativeFunction(findLdpSym('socket'),        'int', ['int', 'int', 'int']),
    bind:          new NativeFunction(findLdpSym('bind'),          'int', ['int', 'pointer', 'int']),
    connect:       new NativeFunction(findLdpSym('connect'),       'int', ['int', 'pointer', 'int']),
    setsockopt:    new NativeFunction(findLdpSym('setsockopt'),    'int', ['int', 'int', 'int', 'pointer', 'int']),
    getsockopt:    new NativeFunction(findLdpSym('getsockopt'),    'int', ['int', 'int', 'int', 'pointer', 'pointer']),
    getsockname:   new NativeFunction(findLdpSym('getsockname'),   'int', ['int', 'pointer', 'pointer']),
    read:          new NativeFunction(findLdpSym('read'),          'int', ['int', 'pointer', 'int']),
    write:         new NativeFunction(findLdpSym('write'),         'int', ['int', 'pointer', 'int']),
    close:         new NativeFunction(findLdpSym('close'),         'int', ['int']),
    epoll_create1: new NativeFunction(findLdpSym('epoll_create1'), 'int', ['int']),
    epoll_ctl:     new NativeFunction(findLdpSym('epoll_ctl'),     'int', ['int', 'int', 'int', 'pointer']),
    epoll_wait:    new NativeFunction(findLdpSym('epoll_wait'),    'int', ['int', 'pointer', 'int', 'int']),
};

/* C errno helper */
const errnoLocation = new NativeFunction(
    findExport('libc.so.6', '__errno_location'), 'pointer', []
);
function getCErrno() { return errnoLocation().readInt(); }

/* Pre-cached Go error interface objects from the binary. */
var goErrSyms = {};
var goErrnoItab = null;  // go:itab.syscall.Errno,error
(function findGoErrSymbols() {
    var wanted = ['syscall.errEAGAIN', 'syscall.errEINVAL', 'syscall.errENOENT',
                  'go:itab.syscall.Errno,error'];
    Process.getModuleByName(moduleName).enumerateSymbols().forEach(function(sym) {
        if (wanted.indexOf(sym.name) !== -1) goErrSyms[sym.name] = sym.address;
    });
    if (goErrSyms['go:itab.syscall.Errno,error']) {
        goErrnoItab = goErrSyms['go:itab.syscall.Errno,error'];
    }
})();

// Returns {itab, data} for a C errno value.
// go:itab.syscall.Errno,error uses pointer receivers, so data must be a pointer to
// a uintptr holding the errno value. We cache allocations per errno value.
var _errnoDataCache = {};
function goErrFromErrno(errno) {
    if (goErrnoItab) {
        if (!_errnoDataCache[errno]) {
            var slot = Memory.alloc(8);
            slot.writeU64(errno);
            _errnoDataCache[errno] = slot;
        }
        return { itab: goErrnoItab, data: _errnoDataCache[errno] };
    }
    var sym;
    if (errno === 11)      sym = goErrSyms['syscall.errEAGAIN'];
    else if (errno === 22) sym = goErrSyms['syscall.errEINVAL'];
    else if (errno === 2)  sym = goErrSyms['syscall.errENOENT'];
    else                   sym = goErrSyms['syscall.errEINVAL'];
    if (!sym) return { itab: ptr(0), data: ptr(0) };
    return { itab: sym.readPointer(), data: sym.add(8).readPointer() };
}

/* Go return value helper.
 * returnsInt=true  → (int, error): rax=int, rbx=err.itab, rcx=err.data
 * returnsInt=false → error:        rax=err.itab, rbx=err.data
 */
function setGoReturn(context, retval, result, syscallName, returnsInt) {
    if (result < 0) {
        var errno = getCErrno();
        var goErr = goErrFromErrno(errno);
        console.log('[!] ' + syscallName + ' failed: ret=' + result + ', errno=' + errno);
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
        console.log('[+] ' + syscallName + ' succeeded: ret=' + result);
        if (returnsInt) {
            retval.replace(result);
            context.rbx = ptr(0);
            context.rcx = ptr(0);
        } else {
            retval.replace(0);
            context.rbx = ptr(0);
            context.rcx = ptr(0);
        }
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
            // Skip MPTCP sockets (proto=262=IPPROTO_MPTCP) — VPP doesn't support MPTCP.
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
            setGoReturn(this.context, retval, ret, 'bind', false);
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
            setGoReturn(this.context, retval, ret, 'getsockname', false);
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
            var e = getCErrno();
            if (ret === -1 && (e === 115 /*EINPROGRESS*/ || e === 114 /*EALREADY*/)) {
                // VCL non-blocking connect: session created but handshake pending
                // (VCL_STATE_UPDATED). Use LDP's epoll to wait for the session to
                // transition to READY. This is necessary because vppcom_session_write
                // does NOT process the VCL message queue — without epoll_wait, the
                // SESSION_CONNECTED event from VPP sits unread in the MQ forever.
                // LDP's epoll_wait calls vppcom_epoll_wait which processes the MQ.
                console.log('[dbg] connect EINPROGRESS → using LDP epoll to wait for READY');
                var epfd = ldp.epoll_create1(0);
                if (epfd >= 0) {
                    // struct epoll_event { uint32_t events; epoll_data_t data; } (12 bytes packed on x86_64)
                    var ev = Memory.alloc(12);
                    ev.writeU32(0x04); // EPOLLOUT
                    ev.add(4).writeU32(this._fd); // data.fd
                    var ctlRet = ldp.epoll_ctl(epfd, 1 /*EPOLL_CTL_ADD*/, this._fd, ev);
                    console.log('[dbg] epoll_ctl(ADD, fd=' + this._fd + ') = ' + ctlRet);
                    if (ctlRet === 0) {
                        var events = Memory.alloc(12);
                        var n = ldp.epoll_wait(epfd, events, 1, 5000); // 5s timeout
                        console.log('[dbg] epoll_wait returned n=' + n);
                        if (n > 0) {
                            console.log('[dbg] POLLOUT fired — session READY');
                        } else {
                            console.log('[!] epoll_wait timeout/error — session may not be connected');
                        }
                    }
                    ldp.close(epfd);
                } else {
                    console.log('[!] epoll_create1 failed: ' + epfd + ' errno=' + getCErrno());
                }
                retval.replace(0);
                this.context.rbx = ptr(0);
                this.context.rcx = ptr(0);
                return;
            }
            setGoReturn(this.context, retval, ret, 'connect', false);
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
            setGoReturn(this.context, retval, ret, 'setsockopt', false);
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
            setGoReturn(this.context, retval, ret, 'getsockopt', false);
        }
    });
    console.log('[+] Hooked syscall.getsockopt');
})();

// --- read(fd, buf, count) → int ---
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
            var fd = this._fd;
            var buf = ptr(this._buf.toString());
            var len = this._len;
            var ret = ldp.read(fd, buf, len);
            if (ret === -1 && getCErrno() === 11 && fd >= 32) {
                // EAGAIN on VCL fd: use epoll_wait to process VCL MQ and wait for data.
                // Without epoll_wait, the MQ event (data available) is never processed
                // and ldp.read keeps returning EAGAIN forever.
                var epfd = ldp.epoll_create1(0);
                if (epfd >= 0) {
                    var ev = Memory.alloc(12);
                    ev.writeU32(0x01); // EPOLLIN
                    ev.add(4).writeU32(fd);
                    ldp.epoll_ctl(epfd, 1 /*EPOLL_CTL_ADD*/, fd, ev);
                    var events = Memory.alloc(12);
                    var n = ldp.epoll_wait(epfd, events, 1, 5000); // 5s timeout
                    ldp.close(epfd);
                    if (n > 0) {
                        ret = ldp.read(fd, buf, len);
                    }
                }
            }
            setGoReturn(this.context, retval, ret, 'read', true);
        }
    });
    console.log('[+] Hooked syscall.read');
})();

// --- write(fd, buf, count) → int ---
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
            console.log('[>] write(fd=' + this._fd + ', len=' + this._len + ')');
        },
        onLeave: function(retval) {
            var fd = this._fd;
            var buf = ptr(this._buf.toString());
            var len = this._len;
            var ret = ldp.write(fd, buf, len);
            var e = getCErrno();
            // If EAGAIN or ENOTCONN on VCL fd, use epoll to wait for writability
            if (ret === -1 && (e === 11 || e === 107) && fd >= 32) {
                var epfd = ldp.epoll_create1(0);
                if (epfd >= 0) {
                    var ev = Memory.alloc(12);
                    ev.writeU32(0x04); // EPOLLOUT
                    ev.add(4).writeU32(fd);
                    ldp.epoll_ctl(epfd, 1 /*EPOLL_CTL_ADD*/, fd, ev);
                    var events = Memory.alloc(12);
                    var n = ldp.epoll_wait(epfd, events, 1, 5000);
                    ldp.close(epfd);
                    if (n > 0) {
                        ret = ldp.write(fd, buf, len);
                    }
                }
            }
            setGoReturn(this.context, retval, ret, 'write', true);
        }
    });
    console.log('[+] Hooked syscall.write');
})();

// --- close(fd) → error ---
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

console.log('[+] All client hooks installed. Go syscalls will be redirected to VCL.');
}
