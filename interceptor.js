/* Setup */
/*
        1. apt update
        2. apt instal python3-pip
        3. pip3 install frida
        4. pip3 install frida-tools
        5. apt install less (for debugging with objdump)
                eg) objdump -lSd /usr/lib/libvcl_ldpreload.so | less
        6. Compile the assmebly patch code to hack register mismatch between Go ABI and SystemV ABI
                i)  nasm -f elf64 -DPIC prepRegs.asm
                ii) gcc -shared -fPIC prepRegs.o -o libPrepRegs.so
        7. Create a hst test framework and persist it
                i) sudo make test-debug PERSIST=true TEST=LDPreloadIperfVppTest
        7. Copy the libraries, binary and interception.js script to the docker containers
                i)   docker cp libvcl_ldpreload.so <container_id>:/usr/lib/libvcl_ldpreload.so
                ii)  docker cp libPrepRegs.so <container_id>:/usr/lib/libPrepRegs.so
                iii) docker cp test_server_go <container_id>:/usr/bin/test_server_go
                iv)  docker cp interception.js <container_id>:/usr/bin/interception.js
        8. Run test binary with Frida
                eg) VCL_CONFIG=/tmp/server-share/vcl.conf frida /usr/bin/test_server_go -l interceptor.js
                NOTE: binary path must be absolute, interceptor script path can be relative
        *** How to figure out the system calls to intercept? ***
                i) Run the binary with strace and check for the libc syscalls
                        eg) strace -f -e trace=network test_server_go [socket, setsockopt, bind, listen, getsockname, accept4] [socket, getsockopt, connect]
                ii) Then use gdb on the binary to trace it back to the Go syscalls
                        eg) gdb test_server_go [b syscall.socket, b syscall.setsockopt, b syscall.bind, b syscall.Listen, b syscall.getsockname, b syscall.accept4, r]
                iii) Generally the Go syscall flow is like this:
                        syscall.Socket ==> syscall.socket ==> syscall.RawSyscall ==> syscall.RawSyscall6 ==> ASM code to manipulate registers as per SystemV ABI standards ==> SYSCALL
*/



/* Find the addresses of Go syscalls */
const moduleName = 'test_server_go';
const syscalls = ['syscall.socket', 'syscall.setsockopt', 'syscall.bind', 'syscall.Listen', 'syscall.getsockname', 'syscall.accept4', 'syscall.getsockopt', 'syscall.connect'];

// Create a hashmap to store the addresses of each Go syscall (to be used in interception later)
const syscallAddresses = {};

// Store the address of a given Go syscall
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

// Store the addresses of all Go syscalls
syscalls.forEach(setupInterceptor);



/* Load the required modules in the process address space */
const modules = [
        '/usr/lib/libvcl_ldpreload.so', // VCL LD Preload library
        '/usr/lib/libPrepRegs.so' // assembly code to hack register mismatch between Go ABI and SystemV ABI
];

// Check if the library is loaded
function checkLibraryLoaded(moduleName) {
        let loaded = false;

        Process.enumerateModules({
                onMatch: function(module) {
                        if (module.name === moduleName) {
                                loaded = true;
                                console.log(`${module.name} is loaded at ${module.base}`);
                        }
                },
                onComplete: function() {
                        if (!loaded) {
                                console.log(`${moduleName} is not loaded.`);
                        }
                }
        });

        return loaded;
}

// Load the library if not loaded
function loadLibrary(moduleName) {
        const myLib = Module.load(moduleName);
        if (myLib) {
                console.log(`${moduleName} loaded successfully.`);
        } else {
                console.log(`Failed to load ${moduleName}`);
        }
}

// Main execution
modules.forEach(moduleName => {
        if (!checkLibraryLoaded(moduleName)) {
                loadLibrary(moduleName);
        }
});



/* Logging for debugging */
const prepRegsAddress = Module.findExportByName('/usr/lib/libPrepRegs.so', 'prepRegs');
const prepRegsFunction = new NativeFunction(prepRegsAddress, 'void', []);

const prepRegs6Address = Module.findExportByName('/usr/lib/libPrepRegs.so', 'prepRegs6');
const prepRegs6Function = new NativeFunction(prepRegs6Address, 'void', []);

const prepRegsAddress2 = Module.findExportByName('/usr/lib/libPrepRegs.so', 'prepRegs2');
const prepRegsFunction2 = new NativeFunction(prepRegsAddress2, 'void', []);

const prepRegsAddress3 = Module.findExportByName('/usr/lib/libPrepRegs.so', 'prepRegs3');
const prepRegsFunction3 = new NativeFunction(prepRegsAddress3, 'void', []);

const prepRegsAddress4 = Module.findExportByName('/usr/lib/libPrepRegs.so', 'prepRegs4');
const prepRegsFunction4 = new NativeFunction(prepRegsAddress4, 'void', []);

const prepRegsAddress5 = Module.findExportByName('/usr/lib/libPrepRegs.so', 'prepRegs5');
const prepRegsFunction5 = new NativeFunction(prepRegsAddress5, 'void', []);

const originalSocket = syscallAddresses['syscall.socket'];
const ldpSocketAddress = Module.findExportByName('/usr/lib/libvcl_ldpreload.so', 'socket');
const ldpSocketFunction = new NativeFunction(ldpSocketAddress, 'int', ['int', 'int', 'int']);

const originalSetSockOpt = syscallAddresses['syscall.setsockopt'];
const ldpSetSockOptAddress = Module.findExportByName('/usr/lib/libvcl_ldpreload.so', 'setsockopt');
const ldpSetSockOptFunction = new NativeFunction(ldpSetSockOptAddress, 'int', ['int', 'int', 'int', 'pointer', 'int']);

const originalBind = syscallAddresses['syscall.bind'];
const ldpBindAddress = Module.findExportByName('/usr/lib/libvcl_ldpreload.so', 'bind');
const ldpBindFunction = new NativeFunction(ldpBindAddress, 'int', ['int', 'pointer', 'int']);

const originalListen = syscallAddresses['syscall.Listen'];
const ldpListenAddress = Module.findExportByName('/usr/lib/libvcl_ldpreload.so', 'listen');
const ldpListenFunction = new NativeFunction(ldpListenAddress, 'int', ['int', 'int']);

const originalGetSockName = syscallAddresses['syscall.getsockname'];
const ldpGetSockNameAddress = Module.findExportByName('/usr/lib/libvcl_ldpreload.so', 'getsockname');
const ldpGetSockNameFunction = new NativeFunction(ldpGetSockNameAddress, 'int', ['int', 'pointer', 'pointer']);

const originalAccept4 = syscallAddresses['syscall.accept4'];
const ldpAccept4Address = Module.findExportByName('/usr/lib/libvcl_ldpreload.so', 'accept4');
const ldpAccept4Function = new NativeFunction(ldpAccept4Address, 'int', ['int', 'pointer', 'pointer', 'int']);

console.log(`prepRegsAddress: ${prepRegsAddress}`); // socket
console.log(`prepRegs6Address: ${prepRegs6Address}`); // setsockopt
console.log(`prepRegsAddress2: ${prepRegsAddress2}`); // bind
console.log(`prepRegsAddress3: ${prepRegsAddress3}`); // listen
console.log(`prepRegsAddress4: ${prepRegsAddress4}`); // getsockname
console.log(`prepRegsAddress5: ${prepRegsAddress5}`); // accept4

console.log(`originalSocket address: ${originalSocket}`);
console.log(`ldpSocketAddress: ${ldpSocketAddress}`);

console.log(`originalSetSockOpt address: ${originalSetSockOpt}`);
console.log(`ldpSetSockOptAddress: ${ldpSetSockOptAddress}`);

console.log(`originalBind address: ${originalBind}`);
console.log(`ldpBindAddress: ${ldpBindAddress}`);

console.log(`originalListen address: ${originalListen}`);
console.log(`ldpListenAddress: ${ldpListenAddress}`);

console.log(`originalGetSockName address: ${originalGetSockName}`);
console.log(`ldpGetSockNameAddress: ${ldpGetSockNameAddress}`);

console.log(`originalAccept4 address: ${originalAccept4}`);
console.log(`ldpAccept4Address: ${ldpAccept4Address}`);

function inspectContext(context) {
        // Inspect the registers
        var registers = context;
        console.log('Registers:', JSON.stringify(registers, null, 2));
        // Inspect the stack
        var stackPointer = context.sp;
        console.log('Stack pointer:', stackPointer);
}



// /* HACK */
// function createReplacementWrapper(originalFunc, replacementFunc, returnType, argTypes) {
//         return new NativeCallback(function() {
//             this.originalFunc = originalFunc;
//             return replacementFunc.apply(this, arguments);
//         }, returnType, argTypes);
//     }
    
//     // Now, when calling createReplacementWrapper, provide the return type and argument types
//     const wrapperSocket = createReplacementWrapper(
//         originalSocket, 
//         prepRegsFunction,
//         'int',  // Assuming socket() returns an int
//         ['int', 'int', 'int']  // Assuming socket(int domain, int type, int protocol)
//     );
    
//     const wrapperBind = createReplacementWrapper(
//         originalBind, 
//         prepRegsFunction,
//         'int',  // Assuming bind() returns an int
//         ['int', 'pointer', 'int']  // Assuming bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
//     );
    

// Interceptor.replace(originalSocket, wrapperSocket);
// Interceptor.replace(originalSetSockOpt, prepRegs6Function);
// Interceptor.replace(originalBind, wrapperBind);

// Interceptor.attach(originalSocket, {
//         onEnter: function() {
//                 console.log('Intercepted originalSocket call');
//                 inspectContext(this.context)
//         },
//         onLeave: function(retval) {
//                 console.log('originalSocket return value:', retval.toInt32());
//                 var registers = this.context;
//                 console.log('Registers:', JSON.stringify(registers, null, 2));

//                 // // intentionally added to stop stop execution for debugging
//                 // send('Pausing execution. Inspect registers.');
//                 // recv('resume', function(value) {
//                 //         console.log('Resuming execution.');
//                 // }).wait();                          
//         }    
// });

// Interceptor.attach(originalSetSockOpt, {
//         onEnter: function() {
//                 console.log('Intercepted originalSetSockOpt call');
//                 inspectContext(this.context)
//         },
//         onLeave: function(retval) {
//                 console.log('originalSetSockOpt return value:', retval.toInt32());
//                 var registers = this.context;
//                 console.log('Registers:', JSON.stringify(registers, null, 2));

//                 // // intentionally added to stop stop execution for debugging
//                 // send('Pausing execution. Inspect registers.');
//                 // recv('resume', function(value) {
//                 //         console.log('Resuming execution.');
//                 // }).wait();                                            
//         }    
// });

// Interceptor.attach(originalBind, {
//         onEnter: function() {
//                 console.log('Intercepted originalBind call');
//                 inspectContext(this.context)
//         },
//         onLeave: function(retval) {
//                 console.log('originalBind return value:', retval.toInt32());
//                 var registers = this.context;
//                 console.log('Registers:', JSON.stringify(registers, null, 2));
                
//                 // // intentionally added to stop stop execution for debugging
//                 // send('Pausing execution. Inspect registers.');
//                 // recv('resume', function(value) {
//                 //         console.log('Resuming execution.');
//                 // }).wait();                 
//         }    
// });
  
  
// Interceptor.attach(prepRegs6Function, {
//         onEnter: function() {
//                 console.log('Intercepted prepRegs6Function call');
//                 inspectContext(this.context)
//         },
//         onLeave: function(retval) {
//                 console.log('prepRegs6Function OnLeave calling ldpSetSockOptFunction');
//                 inspectContext(this.context)                     
//                 // call the ldpSetSockOptFunction
//                 var ret = ldpSetSockOptFunction(this.context.rdi.toInt32(), this.context.rsi.toInt32(), this.context.rdx.toInt32(), this.context.rcx, this.context.r8.toInt32());
//                 console.log('ldpSetSockOptFunction returned ', ret);
//                 // replace the return value since we call this from prepRegs6Function but we want to return the value from ldpSetSockOptFunction
//                 retval.replace(ret);
//                 // prepRegs6Address(); // intentionally added for debugging as this will error out since this is not aa NativeFunction that can be called
//         }    
// });

// // Attach to all wrapper functions
// [wrapperSocket, wrapperBind].forEach(wrapper => {
//         Interceptor.attach(wrapper, {
//           onEnter: function(args) {
//             // Check which original function was replaced
//             if (this.originalFunc === originalSocket) {
//                 console.log('Intercepted originalSocket call');
//                 inspectContext(this.context)                
//             } else if (this.originalFunc === originalBind) {
//                 console.log('Intercepted originalBind call');
//                 inspectContext(this.context)
//             }
//           },
//           onLeave: function(args) {
//                 // Check which original function was replaced
//                 if (this.originalFunc === originalSocket) {
//                         console.log('prepRegsFunction OnLeave calling ldpSocketFunction');
//                         inspectContext(this.context)
//                         // call the ldpSocketFunction
//                         var ret = ldpSocketFunction(this.context.rdi.toInt32(), this.context.rsi.toInt32(), this.context.rdx.toInt32());
//                         console.log('ldpSocketFunction returned ', ret);
//                         // replace the return value since we call this from prepRegsFunction but we want to return the value from ldpSocketFunction
//                         retval.replace(ret);
//                         // prepRegsAddress(); // intentionally added for debugging as this will error out since this is not aa NativeFunction that can be called                 
//                 } else if (this.originalFunc === originalBind) {
//                         console.log('prepRegsFunction OnLeave calling ldpBindFunction');
//                         inspectContext(this.context)                 
//                         // call the ldpBindFunction
//                         var ret = ldpBindFunction(this.context.rdi.toInt32(), this.context.rsi, this.context.rdx.toInt32());
//                         console.log('ldpBindFunction returned ', ret);
//                         // replace the return value since we call this from prepRegsFunction but we want to return the value from ldpBindFunction
//                         retval.replace(ret);
//                         // prepRegsAddress(); // intentionally added for debugging as this will error out since this is not aa NativeFunction that can be called                        
//                 }
//           }          
//         });
// });

/* Interception of socket() call */
if (originalSocket && prepRegsAddress && ldpSocketAddress) {

        Interceptor.replace(originalSocket, prepRegsFunction);

        Interceptor.attach(originalSocket, {
                onEnter: function() {
                        console.log('Intercepted originalSocket call');
                        inspectContext(this.context)
                },
                onLeave: function(retval) {
                        console.log('originalSocket return value:', retval.toInt32());
                        var registers = this.context;
                        console.log('Registers:', JSON.stringify(registers, null, 2));

                        // // intentionally added to stop stop execution for debugging
                        // send('Pausing execution. Inspect registers.');
                        // recv('resume', function(value) {
                        //         console.log('Resuming execution.');
                        // }).wait();                          
                }    
                });
  
        Interceptor.attach(prepRegsFunction, {
                onEnter: function() {
                        console.log('Intercepted prepRegsFunction call');
                        inspectContext(this.context)
                },
                onLeave: function(retval) {
                        console.log('prepRegsFunction OnLeave calling ldpSocketFunction');
                        inspectContext(this.context)
                        // call the ldpSocketFunction
                        var ret = ldpSocketFunction(this.context.rdi.toInt32(), this.context.rsi.toInt32(), this.context.rdx.toInt32());
                        console.log('ldpSocketFunction returned ', ret);
                        // replace the return value since we call this from prepRegsFunction but we want to return the value from ldpSocketFunction
                        retval.replace(ret);
                        // prepRegsAddress(); // intentionally added for debugging as this will error out since this is not aa NativeFunction that can be called
                }    
                });
} else {
        console.log("socket related function(s) not found!");
}



/* Interception of setsockopt() call */
if (originalSetSockOpt && prepRegs6Address && ldpSetSockOptAddress) {

        Interceptor.replace(originalSetSockOpt, prepRegs6Function);

        Interceptor.attach(originalSetSockOpt, {
                onEnter: function() {
                        console.log('Intercepted originalSetSockOpt call');
                        inspectContext(this.context)
                },
                onLeave: function(retval) {
                        console.log('originalSetSockOpt return value:', retval.toInt32());
                        var registers = this.context;
                        console.log('Registers:', JSON.stringify(registers, null, 2));

                        // // intentionally added to stop stop execution for debugging
                        // send('Pausing execution. Inspect registers.');
                        // recv('resume', function(value) {
                        //         console.log('Resuming execution.');
                        // }).wait();                                            
                }    
                });
  
        Interceptor.attach(prepRegs6Function, {
                onEnter: function() {
                        console.log('Intercepted prepRegs6Function call');
                        inspectContext(this.context)
                },
                onLeave: function(retval) {
                        console.log('prepRegs6Function OnLeave calling ldpSetSockOptFunction');
                        inspectContext(this.context)                     
                        // call the ldpSetSockOptFunction
                        var ret = ldpSetSockOptFunction(this.context.rdi.toInt32(), this.context.rsi.toInt32(), this.context.rdx.toInt32(), this.context.rcx, this.context.r8.toInt32());
                        console.log('ldpSetSockOptFunction returned ', ret);
                        // replace the return value since we call this from prepRegs6Function but we want to return the value from ldpSetSockOptFunction
                        retval.replace(ret);
                        // prepRegs6Address(); // intentionally added for debugging as this will error out since this is not aa NativeFunction that can be called
                }    
                });
} else {
        console.log("setsockopt related function(s) not found!");
}



/* Interception of bind() call */
if (originalBind && prepRegsAddress2 && ldpBindAddress) {

        Interceptor.replace(originalBind, prepRegsFunction2);

        Interceptor.attach(originalBind, {
                onEnter: function() {
                        console.log('Intercepted originalBind call');
                        inspectContext(this.context)
                },
                onLeave: function(retval) {
                        console.log('originalBind return value:', retval.toInt32());
                        var registers = this.context;
                        console.log('Registers:', JSON.stringify(registers, null, 2));

                        // // intentionally added to stop stop execution for debugging
                        // send('Pausing execution. Inspect registers.');
                        // recv('resume', function(value) {
                        //         console.log('Resuming execution.');
                        // }).wait();                         
                }    
                });
  
        Interceptor.attach(prepRegsFunction2, {
                onEnter: function() {
                        console.log('Intercepted prepRegsFunction2 call');
                        inspectContext(this.context)
                },
                onLeave: function(retval) {
                        console.log('prepRegsFunction2 OnLeave calling ldpBindFunction');
                        inspectContext(this.context)                 
                        // call the ldpBindFunction
                        var ret = ldpBindFunction(this.context.rdi.toInt32(), this.context.rsi, this.context.rdx.toInt32());
                        console.log('ldpBindFunction returned ', ret);
                        // replace the return value since we call this from prepRegsFunction but we want to return the value from ldpBindFunction
                        retval.replace(ret);
                        
                        // prepRegsAddress2(); // intentionally added for debugging as this will error out since this is not aa NativeFunction that can be called
                }    
                });
} else {
        console.log("bind related function(s) not found!");
}


/* Interception of listen() call */
if (originalListen && prepRegsAddress3 && ldpListenAddress) {

        Interceptor.replace(originalListen, prepRegsFunction3);

        Interceptor.attach(originalListen, {
                onEnter: function() {
                        console.log('Intercepted originalListen call');
                        inspectContext(this.context)
                },
                onLeave: function(retval) {
                        console.log('originalListen return value:', retval.toInt32());
                        var registers = this.context;
                        console.log('Registers:', JSON.stringify(registers, null, 2));

                        // // intentionally added to stop stop execution for debugging
                        // send('Pausing execution. Inspect registers.');
                        // recv('resume', function(value) {
                        //         console.log('Resuming execution.');
                        // }).wait();                         
                }    
                });
  
        Interceptor.attach(prepRegsFunction3, {
                onEnter: function() {
                        console.log('Intercepted prepRegsFunction3 call');
                        inspectContext(this.context)
                },
                onLeave: function(retval) {
                        console.log('prepRegsFunction3 OnLeave calling ldpListenFunction');
                        inspectContext(this.context)                 
                        // call the ldpListenFunction
                        var ret = ldpListenFunction(this.context.rdi.toInt32(), this.context.rsi.toInt32());
                        console.log('ldpListenFunction returned ', ret);
                        // replace the return value since we call this from prepRegsFunction but we want to return the value from ldpListenFunction
                        retval.replace(ret);
                        
                        // prepRegsAddress3(); // intentionally added for debugging as this will error out since this is not aa NativeFunction that can be called
                }    
                });
} else {
        console.log("listen related function(s) not found!");
}


/* Interception of getsockname() call */
if (originalGetSockName && prepRegsAddress4 && ldpGetSockNameAddress) {

        Interceptor.replace(originalGetSockName, prepRegsFunction4);

        Interceptor.attach(originalGetSockName, {
                onEnter: function() {
                        console.log('Intercepted originalGetSockName call');
                        inspectContext(this.context)
                },
                onLeave: function(retval) {
                        console.log('originalGetSockName return value:', retval.toInt32());
                        var registers = this.context;
                        console.log('Registers:', JSON.stringify(registers, null, 2));

                        // // intentionally added to stop stop execution for debugging
                        // send('Pausing execution. Inspect registers.');
                        // recv('resume', function(value) {
                        //         console.log('Resuming execution.');
                        // }).wait();                         
                }    
                });
  
        Interceptor.attach(prepRegsFunction4, {
                onEnter: function() {
                        console.log('Intercepted prepRegsFunction4 call');
                        inspectContext(this.context)
                },
                onLeave: function(retval) {
                        console.log('prepRegsFunction4 OnLeave calling ldpGetSockNameFunction');
                        inspectContext(this.context)                 
                        // call the ldpGetSockNameFunction
                        var ret = ldpGetSockNameFunction(this.context.rdi.toInt32(), this.context.rsi, this.context.rdx);
                        console.log('ldpGetSockNameFunction returned in var', ret);
                        // replace the return value since we call this from prepRegsFunction but we want to return the value from ldpGetSockNameFunction
                        retval.replace(ret);
                        
                        // prepRegsAddress4(); // intentionally added for debugging as this will error out since this is not aa NativeFunction that can be called
                }    
                });
} else {
        console.log("getsockname related function(s) not found!");
}




/* Interception of accept4() call */
if (originalAccept4 && prepRegsAddress5 && ldpAccept4Address) {

        Interceptor.replace(originalAccept4, prepRegsFunction5);

        Interceptor.attach(originalAccept4, {
                onEnter: function() {
                        console.log('Intercepted originalAccept4 call');
                        inspectContext(this.context)
                },
                onLeave: function(retval) {
                        console.log('originalAccept4 return value:', retval.toInt32());
                        var registers = this.context;
                        console.log('Registers:', JSON.stringify(registers, null, 2));

                        // // intentionally added to stop stop execution for debugging
                        // send('Pausing execution. Inspect registers.');
                        // recv('resume', function(value) {
                        //         console.log('Resuming execution.');
                        // }).wait();                         
                }    
                });
  
        Interceptor.attach(prepRegsFunction5, {
                onEnter: function() {
                        console.log('Intercepted prepRegsFunction5 call');
                        inspectContext(this.context)
                },
                onLeave: function(retval) {
                        console.log('prepRegsFunction5 OnLeave calling ldpAccept4Function');
                        inspectContext(this.context)                 
                        // call the ldpAccept4Function
                        var ret = ldpAccept4Function(this.context.rdi.toInt32(), this.context.rsi, this.context.rdx, this.context.rcx.toInt32());
                        console.log('ldpAccept4Function returned ', ret);
                        // replace the return value since we call this from prepRegsFunction but we want to return the value from ldpAccept4Function
                        retval.replace(ret);
                        
                        // prepRegsAddress5(); // intentionally added for debugging as this will error out since this is not aa NativeFunction that can be called
                }    
                });
} else {
        console.log("accept4 related function(s) not found!");
}