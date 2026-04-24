// Check if the target library is loaded
var moduleName = '/usr/lib/libvcl_ldpreload.so';
var loaded = false;

// Enumerate modules to check for the specific library
Process.enumerateModules({
    onMatch: function(module) {
        if (module.name === moduleName) {
            loaded = true;
            console.log(module.name + ' is loaded at ' + module.base);
        }
    },
    onComplete: function() {
        if (!loaded) {
            console.log(moduleName + ' is not loaded.');
        }
    }
});

// You can also attempt to load the library if it's not loaded automatically
const myLib = Module.load(moduleName); // Load it explicitly
if (myLib) {
    console.log(moduleName + ' loaded successfully.');
} else {
    console.log('Failed to load ' + moduleName);
}

// interceptor.js
const originalSocket = Module.findExportByName(null, 'socket');
const originalBind = Module.findExportByName(null, 'bind');
const originalListen = Module.findExportByName(null, 'listen');
const originalSelect = Module.findExportByName(null, 'select');
const originalSetsockopt = Module.findExportByName(null, 'setsockopt');
const originalGetsockname = Module.findExportByName(null, 'getsockname');

// Check if the original select function is found
if (originalSelect) {
        // Get the address of the select function from the library
        const vclSelect = Module.findExportByName('/usr/lib/libvcl_ldpreload.so', 'select');

        if (vclSelect) {
                Interceptor.replace(originalSelect, new NativeFunction(vclSelect, 'int', ['int', 'pointer', 'pointer', 'pointer', 'pointer']));

                Interceptor.attach(originalSelect, {
                        onEnter: function(args) {
                                console.log('Intercepted select call');
                                // Log arguments if needed
                                console.log('arg1:', args[0].toInt32()); // nfds
                                console.log('arg2:', args[1]); // readfds (pointer)
                                console.log('arg3:', args[2]); // writefds (pointer)
                                console.log('arg4:', args[3]); // exceptfds (pointer)
                                console.log('arg5:', args[4]); // timeout (pointer)
                        },
                        onLeave: function(retval) {
                                console.log('Original select return value:', retval.toInt32());
                        }
                });
        } else {
                console.log('vcl_select function not found in libvcl_ldpreload.so.');
        }
} else {
        console.log('Original select function not found.');
}

// Function to hook listen
if (originalListen) {
        const vclListen = Module.findExportByName('/usr/lib/libvcl_ldpreload.so', 'listen');

        if (vclListen) {
                Interceptor.replace(originalListen, new NativeFunction(vclListen, 'int', ['int', 'int']));

                Interceptor.attach(originalListen, {
                        onEnter: function(args) {
                                console.log('Intercepted listen call');
                                console.log('arg1 (socket):', args[0].toInt32()); // socket
                                console.log('arg2 (backlog):', args[1].toInt32()); // backlog
                        },
                        onLeave: function(retval) {
                                console.log('Original listen return value:', retval.toInt32());
                        }
                });
        } else {
                console.log('vcl_listen function not found in libvcl_ldpreload.so.');
        }
} else {
        console.log('Original listen function not found.');
}

// Function to hook bind
if (originalBind) {
        const vclBind = Module.findExportByName('/usr/lib/libvcl_ldpreload.so', 'bind');

        if (vclBind) {
                Interceptor.replace(originalBind, new NativeFunction(vclBind, 'int', ['int', 'pointer', 'uint']));

                Interceptor.attach(originalBind, {
                        onEnter: function(args) {
                                console.log('Intercepted bind call');
                                console.log('arg1 (socket):', args[0].toInt32()); // socket
                                console.log('arg2 (addr):', args[1]); // addr (pointer)
                                console.log('arg3 (addrlen):', args[2].toInt32()); // addrlen
                        },
                        onLeave: function(retval) {
                                console.log('Original bind return value:', retval.toInt32());
                        }
                });
        } else {
                console.log('vcl_bind function not found in libvcl_ldpreload.so.');
        }
} else {
        console.log('Original bind function not found.');
}

// Function to hook socket
if (originalSocket) {
        const vclSocket = Module.findExportByName('/usr/lib/libvcl_ldpreload.so', 'socket');

        if (vclSocket) {
                Interceptor.replace(originalSocket, new NativeFunction(vclSocket, 'int', ['int', 'int', 'int']));

                Interceptor.attach(originalSocket, {
                        onEnter: function(args) {
                                console.log('Intercepted socket call');
                                console.log('arg1 (domain):', args[0].toInt32()); // domain
                                console.log('arg2 (type):', args[1].toInt32()); // type
                                console.log('arg3 (protocol):', args[2].toInt32()); // protocol
                        },
                        onLeave: function(retval) {
                                console.log('Original socket return value:', retval.toInt32());
                        }
                });
        } else {
                console.log('vcl_socket function not found in libvcl_ldpreload.so.');
        }
} else {
        console.log('Original socket function not found.');
}

// Function to hook setsockopt
if (originalSetsockopt) {
        const vclSetsockopt = Module.findExportByName('/usr/lib/libvcl_ldpreload.so', 'setsockopt');

        if (vclSetsockopt) {
                Interceptor.replace(originalSetsockopt, new NativeFunction(vclSetsockopt, 'int', ['int', 'int', 'int', 'pointer', 'int']));

                Interceptor.attach(originalSetsockopt, {
                        onEnter: function(args) {
                                console.log('Intercepted setsockopt call');
                                console.log('arg1 (socket):', args[0].toInt32()); // socket
                                console.log('arg2 (level):', args[1].toInt32()); // level
                                console.log('arg3 (optname):', args[2].toInt32()); // optname
                                console.log('arg4 (optval):', args[3]); // optval (pointer)
                                console.log('arg5 (optlen):', args[4].toInt32()); // optlen
                        },
                        onLeave: function(retval) {
                                console.log('Original setsockopt return value:', retval.toInt32());
                        }
                });
        } else {
                console.log('vcl_setsockopt function not found in libvcl_ldpreload.so.');
        }
} else {
        console.log('Original setsockopt function not found.');
}

// Function to hook getsockname
if (originalGetsockname) {
        const vclGetsockname = Module.findExportByName('/usr/lib/libvcl_ldpreload.so', 'getsockname');

        if (vclGetsockname) {
                Interceptor.replace(originalGetsockname, new NativeFunction(vclGetsockname, 'int', ['int', 'pointer', 'pointer']));

                Interceptor.attach(originalGetsockname, {
                        onEnter: function(args) {
                                console.log('Intercepted getsockname call');
                                console.log('arg1 (socket):', args[0].toInt32()); // socket
                                console.log('arg2 (addr):', args[1]); // addr (pointer)
                                console.log('arg3 (addrlen):', args[2]); // addrlen (pointer)
                        },
                        onLeave: function(retval) {
                                console.log('Original getsockname return value:', retval.toInt32());
                        }
                });
        } else {
                console.log('vcl_getsockname function not found in libvcl_ldpreload.so.');
        }
} else {
        console.log('Original getsockname function not found.');
}