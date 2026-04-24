// Find the addresses of multiple syscalls
const moduleName = 'test_server_go';
const syscalls = ['syscall.socket', 'syscall.setsockopt', 'syscall.bind', 'syscall.Listen', 'syscall.getsockname'];

// Create a hashmap to store the addresses of each syscall
const syscallAddresses = {};

// Function to set up an interceptor for a given syscall
function setupInterceptor(name) {
        Module.enumerateSymbols(moduleName, {
                onMatch: function (exp) {
                        if (exp.name === name) {
                                console.log(`Found ${name} at address: ${exp.address}`);
                                syscallAddresses[name] = exp.address; // Store the address in the hashmap
                        }
                },
                onComplete: function () {
                        console.log(`Finished enumerating exports for ${moduleName}`);
                }
        });
}

// Set up interceptors for all specified syscalls
syscalls.forEach(setupInterceptor);

const MODULE_NAME = '/usr/lib/libvcl_ldpreload.so';

// Check if the target library is loaded
function checkLibraryLoaded() {
        let loaded = false;

        Process.enumerateModules({
                onMatch: function(module) {
                        if (module.name === MODULE_NAME) {
                                loaded = true;
                                console.log(`${module.name} is loaded at ${module.base}`);
                        }
                },
                onComplete: function() {
                        if (!loaded) {
                                console.log(`${MODULE_NAME} is not loaded.`);
                        }
                }
        });

        return loaded;
}

// Load the library if not loaded
function loadLibrary() {
        const myLib = Module.load(MODULE_NAME);
        if (myLib) {
                console.log(`${MODULE_NAME} loaded successfully.`);
        } else {
                console.log(`Failed to load ${MODULE_NAME}`);
        }
}

// Main execution
if (!checkLibraryLoaded()) {
        loadLibrary();
}

// interceptor.js
const originalSocket = syscallAddresses['syscall.socket'];
const originalBind = syscallAddresses['syscall.bind'];
const originalListen = syscallAddresses['syscall.Listen'];
const originalSetsockopt = syscallAddresses['syscall.setsockopt'];
const originalGetsockname = syscallAddresses['syscall.getsockname'];

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
                                console.log('Intercepted originalSocket call');
                                var registers = this.context;
                                console.log('Registers:', JSON.stringify(registers, null, 2));
                                console.log('arg1 (domain):', args[0]); // domain
                                console.log('arg2 (type):', args[1]); // type
                                console.log('arg3 (protocol):', args[2]); // protocol
                        },
                        onLeave: function(retval) {
                                console.log('vclSocket socket return value:', retval.toInt32());
                        }
                });

                Interceptor.attach(vclSocket, {
                        onEnter: function(args) {
                                console.log('Intercepted vclSocket call');
                                var registers = this.context;
                                console.log('Registers:', JSON.stringify(registers, null, 2));
                                console.log('arg1 (domain):', args[0]); // domain
                                console.log('arg2 (type):', args[1]); // type
                                console.log('arg3 (protocol):', args[2]); // protocol
                        },
                        onLeave: function(retval) {
                                console.log('vclSocket socket return value:', retval.toInt32());
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