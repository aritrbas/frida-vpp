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


const MODULE_NAME2 = '/usr/lib/test.so';

// Check if the target library is loaded
function checkLibraryLoaded2() {
        let loaded = false;

        Process.enumerateModules({
                onMatch: function(module) {
                        if (module.name === MODULE_NAME2) {
                                loaded = true;
                                console.log(`${module.name} is loaded at ${module.base}`);
                        }
                },
                onComplete: function() {
                        if (!loaded) {
                                console.log(`${MODULE_NAME2} is not loaded.`);
                        }
                }
        });

        return loaded;
}

// Load the library if not loaded
function loadLibrary2() {
        const myLib = Module.load(MODULE_NAME2);
        if (myLib) {
                console.log(`${MODULE_NAME2} loaded successfully.`);
        } else {
                console.log(`Failed to load ${MODULE_NAME2}`);
        }
}

// Main execution
if (!checkLibraryLoaded()) {
        loadLibrary();
}

// // Main execution
// if (!checkLibraryLoaded2()) {
//         loadLibrary2();
// }

// interceptor.js

function getContextInfo(context) {
        const registers = [context.rax, context.rbx, context.rcx, context.rdi, context.rsi, context.r8, context.r9, context.r10, context.r11, context.rdx, context.rip];
        // console.log(`registers[rax]:`, registers[0]);
        // console.log(`registers[rbx]:`, registers[1]);
        // console.log(`registers[rcx]:`, registers[2]);
        // console.log(`registers[rdi]:`, registers[3]);
        // console.log(`registers[rsi]:`, registers[4]);
        // console.log(`registers[r8]:`, registers[5]);
        // console.log(`registers[r9]:`, registers[6]);
        // console.log(`registers[r10]:`, registers[7]);
        // console.log(`registers[r11]:`, registers[8]);
        // console.log(`registers[rdx]:`, registers[9]);
        // console.log(`registers[rip]:`, registers[10]);
        return { registers };
}

// Function to hook socket
const originalSocket = syscallAddresses['syscall.socket'];
if (originalSocket) {
        const vclSocket = Module.findExportByName('/usr/lib/libvcl_ldpreload.so', 'socket');
        if (vclSocket) {        
                Interceptor.attach(originalSocket, {
                        onEnter: function(args) {
                            // Inspect the registers
                            var registers = this.context;
                            console.log('Registers:', JSON.stringify(registers, null, 2));
                    
                            // Inspect the stack
                            var stackPointer = this.context.sp;
                            console.log('Stack pointer:', stackPointer);
                            console.log('Stack contents:', Memory.readByteArray(stackPointer, 64)); // Adjust size as needed                                
                            console.log('Intercepted originalSocket call');
                            this.context.pc = this.returnAddress;
                            try {
                                Memory.protect(originalSocket, Process.pageSize, 'rwx');
                                Memory.patchCode(originalSocket, Process.pageSize, function (code) { // Patch only first 16 bytes
                                    const cw = new X86Writer(code, {pc: originalSocket});
                                    cw.putRet();
                                    cw.flush();
                                });
                                console.log('Successfully patched originalSocket');
                            } catch (error) {
                                console.error('Failed to patch originalSocket:', error);
                            }
                        },
                        onLeave: function(retval) {
                                console.log('originalSocket return value:', retval.toInt32());
                                const contextInfo = getContextInfo(this.context);
                                console.log('arg1 (domain):', contextInfo.registers[0]); // domain
                                console.log('arg2 (type):', contextInfo.registers[1]); // type
                                console.log('arg3 (protocol):', contextInfo.registers[2]); // protocol
                                var ldp_socket = new NativeFunction(Module.findExportByName('/usr/lib/libvcl_ldpreload.so', 'socket'), 'int', ['int', 'int', 'int']);                                  
                                var ret = ldp_socket(contextInfo.registers[0].toInt32(), contextInfo.registers[1].toInt32(), contextInfo.registers[2].toInt32());
                                console.log('ldp_socket return value:', ret);                                
                        }
                });
        } else {
                console.log('vclSocket function not found in libvcl_ldpreload.so.');
        }
} else {
        console.log('Original socket function not found.');
}

// // Function to hook socket
// const originalSocket = syscallAddresses['syscall.socket'];
// if (originalSocket) {
//         const dummySocket = Module.findExportByName('/usr/lib/test.so', 'socket');
//         if (dummySocket) {
//                 // Intercept the original socket function
//                 // Interceptor.attach(originalSocket, {
//                 //                 onEnter: function (args) {
//                 //                                 var registers = this.context;
//                 //                                 console.log('Registers:', JSON.stringify(registers, null, 2));
//                 //                                 console.log("Original socket call with args:", args[0].toInt32(), args[1].toInt32(), args[2].toInt32());
//                 //                                 // Example condition to block execution
//                 //                                 const contextInfo = getContextInfo(this.context);
//                 //                                 var ldp_socket = new NativeFunction(Module.findExportByName('/usr/lib/libvcl_ldpreload.so', 'socket'), 'int', ['int', 'int', 'int']);                                  
//                 //                                 var ret = ldp_socket(contextInfo.registers[0].toInt32(), contextInfo.registers[1].toInt32(), contextInfo.registers[2].toInt32());
//                 //                                 console.log('The value of ret is:', ret);
//                 //                 },
//                 //                 onLeave: function (retval) {
//                 //                                 console.log("Blocked original socket call, returning ", retval.toInt32());
//                 //                 }
//                 // });
//                 // Replace the original function
//                 Interceptor.replace(originalSocket, dummySocket);
//                 Interceptor.attach(originalSocket, {
//                                 onEnter: function (args) {
//                                                 var registers = this.context;
//                                                 console.log('Registers:', JSON.stringify(registers, null, 2));
//                                                 console.log("Original socket call with args:", args[0].toInt32(), args[1].toInt32(), args[2].toInt32());
//                                                 // // Example condition to block execution
//                                                 // const contextInfo = getContextInfo(this.context);
//                                                 // var ldp_socket = new NativeFunction(Module.findExportByName('/usr/lib/libvcl_ldpreload.so', 'socket'), 'int', ['int', 'int', 'int']);                                  
//                                                 // var ret = ldp_socket(contextInfo.registers[0].toInt32(), contextInfo.registers[1].toInt32(), contextInfo.registers[2].toInt32());
//                                                 // console.log('The value of ret is:', ret);
//                                 },
//                                 onLeave: function (retval) {
//                                                 console.log("Blocked original socket call, returning ", retval.toInt32());
//                                 }
//                 });
//                 let ret = 0;
//                 Interceptor.attach(dummySocket, {
//                         onEnter: function (args) {
//                                         var registers = this.context;
//                                         console.log('Registers:', JSON.stringify(registers, null, 2));
//                                         console.log("dummySocket call with args:", args[0].toInt32(), args[1].toInt32(), args[2].toInt32());
//                                         // Example condition to block execution
//                                         const contextInfo = getContextInfo(this.context);
//                                         var ldp_socket = new NativeFunction(Module.findExportByName('/usr/lib/libvcl_ldpreload.so', 'socket'), 'int', ['int', 'int', 'int']);                                  
//                                         ret = ldp_socket(contextInfo.registers[0].toInt32(), contextInfo.registers[1].toInt32(), contextInfo.registers[2].toInt32());
//                                         console.log('The value of ret is:', ret);
//                         },
//                         onLeave: function (retval) {
//                                         retval.replace(ret);
//                                         console.log("Blocked vclSocket socket call, returning ", retval.toInt32());
//                         }
//         });                
//         } else {
//                 console.log('vclSocket function not found in libvcl_ldpreload.so.');
//         }
// } else {
//         console.log('Original socket function not found.');
// }

// // Function to hook getsockname
// const originalGetsockname = syscallAddresses['syscall.getsockname'];
// if (originalGetsockname) {
//         const vclGetsockname = Module.findExportByName('/usr/lib/libvcl_ldpreload.so', 'getsockname');

//         if (vclGetsockname) {
//                 Interceptor.replace(originalGetsockname, new NativeFunction(vclGetsockname, 'int', ['int', 'pointer', 'pointer']));
//                 Interceptor.attach(originalGetsockname, {
//                         onEnter: function(args) {
//                                 // Inspect the registers
//                                 var registers = this.context;
//                                 console.log('Registers:', JSON.stringify(registers, null, 2));
//                                 // Inspect the stack
//                                 var stackPointer = this.context.sp;
//                                 console.log('Stack pointer:', stackPointer);
//                                 console.log('Stack contents:', Memory.readByteArray(stackPointer, 64)); // Adjust size as needed                                
//                                 console.log('Intercepted originalGetsockname call');
//                         },
//                         onLeave: function(retval) {
//                                 console.log('originalGetsockname return value:', retval.toInt32());
//                                 const contextInfo = getContextInfo(this.context);
//                                 console.log('arg1 (socket):', contextInfo.registers[0]); // socket
//                                 console.log('arg2 (addr):', contextInfo.registers[1]); // addr (pointer)
//                                 console.log('arg3 (addrlen):', contextInfo.registers[2]); // addrlen (pointer)
//                                 var ldp_getsockname = new NativeFunction(Module.findExportByName('/usr/lib/libvcl_ldpreload.so', 'getsockname'), 'int', ['int', 'pointer', 'pointer']);
//                                 var ret = ldp_getsockname(contextInfo.registers[0].toInt32(), contextInfo.registers[1], contextInfo.registers[2]);
//                                 console.log('ldp_getsockname return value:', ret);
//                                 retval.replace(ret);
//                         }
//                 });          
//         } else {
//                 console.log('vcl_getsockname function not found in libvcl_ldpreload.so.');
//         }
// } else {
//         console.log('Original getsockname function not found.');
// }

// // Function to hook getsockname
// const originalGetsockname = syscallAddresses['syscall.getsockname'];
// if (originalGetsockname) {
//         const vclGetsockname = Module.findExportByName('/usr/lib/libvcl_ldpreload.so', 'getsockname');

//         if (vclGetsockname) {
//                 Interceptor.replace(originalGetsockname, new NativeFunction(vclGetsockname, 'int', ['int', 'pointer', 'pointer']));
//                 Interceptor.attach(originalGetsockname, {
//                         onEnter: function(args) {
//                                 console.log('Intercepted originalGetsockname call');
//                                 const contextInfo = getContextInfo(this.context);
//                                 this.context.rdi = contextInfo.registers[0]
//                                 this.context.rsi = contextInfo.registers[1]
//                                 this.context.rdx = contextInfo.registers[2]
//                                 this.context.rcx = 0x0
//                                 this.context.r8 = 0x0
//                                 this.context.r9 = 0x0
//                                 this.context.rbx = 0x0
//                                 console.log('arg1 (socket):', contextInfo.registers[0]); // socket
//                                 console.log('arg2 (addr):', contextInfo.registers[1]); // addr (pointer)
//                                 console.log('arg3 (addrlen):', contextInfo.registers[2]); // addrlen (pointer)                              
//                         },
//                         onLeave: function(retval) {
//                                 console.log('originalGetsockname return value:', retval.toInt32());
//                         }
//                 });
//                 Interceptor.attach(vclGetsockname, {
//                         onEnter: function(args) {
//                                 console.log('Intercepted vclGetsockname call');
//                                 const contextInfo = getContextInfo(this.context);
//                                 console.log('arg1 (socket):', contextInfo.registers[3]); // socket
//                                 console.log('arg2 (addr):', contextInfo.registers[4]); // addr (pointer)
//                                 console.log('arg3 (addrlen):', contextInfo.registers[9]); // addrlen (pointer)                              
//                         },
//                         onLeave: function(retval) {
//                                 console.log('vclGetsockname return value:', retval.toInt32());
//                         }
//                 });                
//         } else {
//                 console.log('vcl_getsockname function not found in libvcl_ldpreload.so.');
//         }
// } else {
//         console.log('Original getsockname function not found.');
// }

// // Function to hook bind
// const originalBind = syscallAddresses['syscall.bind'];
// if (originalBind) {
//         const vclBind = Module.findExportByName('/usr/lib/libvcl_ldpreload.so', 'bind');

//         if (vclBind) {
//                 Interceptor.attach(originalBind, {
//                         onEnter: function(args) {
//                                 // Inspect the registers
//                                 var registers = this.context;
//                                 console.log('Registers:', JSON.stringify(registers, null, 2));
//                                 // Inspect the stack
//                                 var stackPointer = this.context.sp;
//                                 console.log('Stack pointer:', stackPointer);
//                                 console.log('Stack contents:', Memory.readByteArray(stackPointer, 64)); // Adjust size as needed                                
//                                 console.log('Intercepted originalBind call');
//                                 const contextInfo = getContextInfo(this.context);
//                                 console.log('arg1 (socket):', contextInfo.registers[0]); // socket
//                                 console.log('arg2 (addr):', contextInfo.registers[1]); // addr (pointer)
//                                 console.log('arg3 (addrlen):', contextInfo.registers[2]); // addrlen
//                                 getContextInfo(this.context);
//                                 var ldp_bind = new NativeFunction(Module.findExportByName('/usr/lib/libvcl_ldpreload.so', 'bind'), 'int', ['int', 'pointer', 'int']);
//                                 ldp_bind(contextInfo.registers[0].toInt32(), contextInfo.registers[1], contextInfo.registers[2].toInt32());                          
//                         },
//                         onLeave: function(retval) {
//                                 console.log('originalBind return value:', retval.toInt32());
//                         }
//                 });               
//         } else {
//                 console.log('vclBind function not found in libvcl_ldpreload.so.');
//         }
// } else {
//         console.log('Original bind function not found.');
// }

// // Function to hook bind
// const originalBind = syscallAddresses['syscall.bind'];
// if (originalBind) {
//         const vclBind = Module.findExportByName('/usr/lib/libvcl_ldpreload.so', 'bind');

//         if (vclBind) {
//                 Interceptor.replace(originalBind, new NativeFunction(vclBind, 'int', ['int', 'pointer', 'uint']));
//                 Interceptor.attach(originalBind, {
//                         onEnter: function(args) {
//                                 console.log('Intercepted originalBind call');
//                                 const contextInfo = getContextInfo(this.context);
//                                 this.context.rdi = contextInfo.registers[0]
//                                 this.context.rsi = contextInfo.registers[1]
//                                 this.context.rdx = contextInfo.registers[2]
//                                 this.context.rcx = 0x0
//                                 this.context.r8 = 0x0
//                                 this.context.r9 = 0x0
//                                 this.context.rbx = 0x0
//                                 console.log('arg1 (socket):', contextInfo.registers[0]); // socket
//                                 console.log('arg2 (addr):', contextInfo.registers[1]); // addr (pointer)
//                                 console.log('arg3 (addrlen):', contextInfo.registers[2]); // addrlen                                          
//                         },
//                         onLeave: function(retval) {
//                                 console.log('originalBind return value:', retval.toInt32());
//                         }
//                 });
//                 Interceptor.attach(vclBind, {
//                         onEnter: function(args) {
//                                 console.log('Intercepted vclBind call');
//                                 const contextInfo = getContextInfo(this.context);
//                                 console.log('arg1 (socket):', contextInfo.registers[3]); // socket
//                                 console.log('arg2 (addr):', contextInfo.registers[4]); // addr (pointer)
//                                 console.log('arg3 (addrlen):', contextInfo.registers[9]); // addrlen                                          
//                         },
//                         onLeave: function(retval) {
//                                 console.log('vclBind return value:', retval.toInt32());
//                         }
//                 });                
//         } else {
//                 console.log('vclBind function not found in libvcl_ldpreload.so.');
//         }
// } else {
//         console.log('Original bind function not found.');
// }

// // Function to hook listen
// const originalListen = syscallAddresses['syscall.Listen'];
// if (originalListen) {
//         const vclListen = Module.findExportByName('/usr/lib/libvcl_ldpreload.so', 'listen');

//         if (vclListen) {
//                 Interceptor.attach(originalListen, {
//                         onEnter: function(args) {
//                                 // Inspect the registers
//                                 var registers = this.context;
//                                 console.log('Registers:', JSON.stringify(registers, null, 2));

//                                 // Inspect the stack
//                                 var stackPointer = this.context.sp;
//                                 console.log('Stack pointer:', stackPointer);
//                                 console.log('Stack contents:', Memory.readByteArray(stackPointer, 64)); // Adjust size as needed       
//                                 console.log('Intercepted originalListen call');
//                         },
//                         onLeave: function(retval) {
//                                 console.log('originalListen return value:', retval.toInt32());
//                                 const contextInfo = getContextInfo(this.context);
//                                 console.log('arg1 (socket):', contextInfo.registers[0]); // socket
//                                 console.log('arg2 (backlog):', contextInfo.registers[1]); // backlog
//                                 var ldp_listen = new NativeFunction(Module.findExportByName('/usr/lib/libvcl_ldpreload.so', 'listen'), 'int', ['int', 'int']);
//                                 var ret = ldp_listen(contextInfo.registers[0].toInt32(), contextInfo.registers[1].toInt32());
//                                 console.log('ldp_listen return value:', ret);
//                         }
//                 });
//         } else {
//                 console.log('vclListen function not found in libvcl_ldpreload.so.');
//         }
// } else {
//         console.log('Original listen function not found.');
// }

// // Function to hook listen
// const originalListen = syscallAddresses['syscall.Listen'];
// if (originalListen) {
//         const vclListen = Module.findExportByName('/usr/lib/libvcl_ldpreload.so', 'listen');

//         if (vclListen) {
//                 Interceptor.replace(originalListen, new NativeFunction(vclListen, 'int', ['int', 'int']));
//                 Interceptor.attach(originalListen, {
//                         onEnter: function(args) {
//                                 console.log('Intercepted originalListen call');
//                                 const contextInfo = getContextInfo(this.context);
//                                 this.context.rdi = contextInfo.registers[0]
//                                 this.context.rsi = contextInfo.registers[1]
//                                 this.context.rdx = contextInfo.registers[2]
//                                 this.context.rcx = 0x0
//                                 this.context.r8 = 0x0
//                                 this.context.r9 = 0x0
//                                 this.context.rbx = 0x0
//                                 console.log('arg1 (socket):', contextInfo.registers[0]); // socket
//                                 console.log('arg2 (backlog):', contextInfo.registers[1]); // backlog
//                         },
//                         onLeave: function(retval) {
//                                 console.log('originalListen return value:', retval.toInt32());
//                         }
//                 });
//                 Interceptor.attach(vclListen, {
//                         onEnter: function(args) {
//                                 console.log('Intercepted vclListen call');
//                                 const contextInfo = getContextInfo(this.context);
//                                 console.log('arg1 (socket):', contextInfo.registers[3]); // socket
//                                 console.log('arg2 (backlog):', contextInfo.registers[4]); // backlog
//                         },
//                         onLeave: function(retval) {
//                                 console.log('vclListen return value:', retval.toInt32());
//                         }
//                 });

//         } else {
//                 console.log('vclListen function not found in libvcl_ldpreload.so.');
//         }
// } else {
//         console.log('Original listen function not found.');
// }

// // Function to hook setsockopt
// const originalSetsockopt = syscallAddresses['syscall.setsockopt'];
// if (originalSetsockopt) {
//         const vclSetsockopt = Module.findExportByName('/usr/lib/libvcl_ldpreload.so', 'setsockopt');

//         if (vclSetsockopt) {
//                 Interceptor.attach(originalSetsockopt, {
//                         onEnter: function(args) {
//                                 // Inspect the registers
//                                 var registers = this.context;
//                                 console.log('Registers:', JSON.stringify(registers, null, 2));

//                                 // Inspect the stack
//                                 var stackPointer = this.context.sp;
//                                 console.log('Stack pointer:', stackPointer);
//                                 console.log('Stack contents:', Memory.readByteArray(stackPointer, 64)); // Adjust size as needed       
//                                 console.log('Intercepted originalSetsockopt call');
//                         },
//                         onLeave: function(retval) {
//                                 console.log('originalSetsockopt return value:', retval.toInt32());
//                                 const contextInfo = getContextInfo(this.context);
//                                 console.log('arg1 (socket):', contextInfo.registers[0]); // socket
//                                 console.log('arg2 (level):', contextInfo.registers[1]); // level
//                                 console.log('arg3 (optname):', contextInfo.registers[2]); // optname
//                                 console.log('arg4 (optval):', contextInfo.registers[3]); // optval (pointer)
//                                 console.log('arg5 (optlen):', contextInfo.registers[4]); // optlen
//                                 var ldp_setsockopt = new NativeFunction(Module.findExportByName('/usr/lib/libvcl_ldpreload.so', 'setsockopt'), 'int', ['int', 'int', 'int', 'pointer', 'int']);
//                                 var ret = ldp_setsockopt(contextInfo.registers[0].toInt32(), contextInfo.registers[1].toInt32(), contextInfo.registers[2].toInt32(), contextInfo.registers[3], contextInfo.registers[4].toInt32());
//                                 console.log('ldp_setsockopt return value:', ret);
//                         }
//                 });            
//         } else {
//                 console.log('vclSetsockopt function not found in libvcl_ldpreload.so.');
//         }
// } else {
//         console.log('Original setsockopt function not found.');
// }

// // Function to hook setsockopt
// const originalSetsockopt = syscallAddresses['syscall.setsockopt'];
// if (originalSetsockopt) {
//         const vclSetsockopt = Module.findExportByName('/usr/lib/libvcl_ldpreload.so', 'setsockopt');

//         if (vclSetsockopt) {
//                 Interceptor.replace(originalSetsockopt, new NativeFunction(vclSetsockopt, 'int', ['int', 'int', 'int', 'pointer', 'int']));
//                 Interceptor.attach(originalSetsockopt, {
//                         onEnter: function(args) {
//                                 console.log('Intercepted originalSetsockopt call');
//                                 const contextInfo = getContextInfo(this.context);
//                                 // [context.rax, context.rbx, context.rcx, context.rdi, context.rsi, context.r8, context.r9, context.r10, context.r11];
//                                 this.context.rdx = contextInfo.registers[2]
//                                 this.context.rcx = contextInfo.registers[3]
//                                 this.context.r8 = contextInfo.registers[4]
//                                 this.context.r9 = 0x0                                
//                                 this.context.rdi = contextInfo.registers[0]
//                                 this.context.rsi = contextInfo.registers[1]
//                                 console.log('arg1 (socket):', contextInfo.registers[0]); // socket
//                                 console.log('arg2 (level):', contextInfo.registers[1]); // level
//                                 console.log('arg3 (optname):', contextInfo.registers[2]); // optname
//                                 console.log('arg4 (optval):', contextInfo.registers[3]); // optval (pointer)
//                                 console.log('arg5 (optlen):', contextInfo.registers[4]); // optlen
//                         },
//                         onLeave: function(retval) {
//                                 console.log('originalSetsockopt return value:', retval.toInt32());
//                         }
//                 });
//                 Interceptor.attach(vclSetsockopt, {
//                         onEnter: function(args) {
//                                 console.log('Intercepted vclSetsockopt call');
//                                 const contextInfo = getContextInfo(this.context);
//                                 console.log('arg1 (socket):', contextInfo.registers[3]); // socket
//                                 console.log('arg2 (level):', contextInfo.registers[4]); // level
//                                 console.log('arg3 (optname):', contextInfo.registers[9]); // optname
//                                 console.log('arg4 (optval):', contextInfo.registers[2]); // optval (pointer)
//                                 console.log('arg5 (optlen):', contextInfo.registers[5]); // optlen
//                         },
//                         onLeave: function(retval) {
//                                 console.log('vclSetsockopt return value:', retval.toInt32());
//                         }
//                 });                
//         } else {
//                 console.log('vclSetsockopt function not found in libvcl_ldpreload.so.');
//         }
// } else {
//         console.log('Original setsockopt function not found.');
// }