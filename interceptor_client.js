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
const moduleName = 'echo_client';
const syscalls = ['syscall.socket', 'syscall.setsockopt', 'syscall.bind', 'syscall.Listen', 'syscall.getsockname', 'syscall.accept4', 'syscall.getsockopt', 'syscall.connect', 'syscall.errEAGAIN', 'go:itab.syscall.Errno,error'];

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

// const updateRegsAddress = Module.findExportByName('/usr/lib/libPrepRegs.so', 'updateRegs');
// const updateRegsFunction = new NativeFunction(updateRegsAddress, 'void', ['int']);

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

const originalGetSockOpt = syscallAddresses['syscall.getsockopt'];
const ldpGetSockOptAddress = Module.findExportByName('/usr/lib/libvcl_ldpreload.so', 'getsockopt');
const ldpGetSockOptFunction = new NativeFunction(ldpGetSockOptAddress, 'int', ['int', 'int', 'int', 'pointer', 'pointer']);

const originalConnect = syscallAddresses['syscall.connect'];
const ldpConnectAddress = Module.findExportByName('/usr/lib/libvcl_ldpreload.so', 'connect');
const ldpConnectFunction = new NativeFunction(ldpConnectAddress, 'int', ['int', 'pointer', 'int']);

const errnoPtrC = Module.findExportByName(null, '__errno_location');
const errnoFuncC = new NativeFunction(errnoPtrC, 'pointer', []);

console.log(`prepRegsAddress: ${prepRegsAddress}`); // <= 3 args
console.log(`prepRegs6Address: ${prepRegs6Address}`); // <= 6 args
// console.log(`updateRegsAddress: ${updateRegsAddress}`);

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

console.log(`originalGetSockOpt address: ${originalGetSockOpt}`);
console.log(`ldpGetSockOptAddress: ${ldpGetSockOptAddress}`);

console.log(`originalConnect address: ${originalConnect}`);
console.log(`ldpConnectAddress: ${ldpConnectAddress}`);

console.log(`__errno_location Address: ${errnoPtrC}`);

function inspectContext(context) {
        // Inspect the registers
        var registers = context;
        console.log('Registers:', JSON.stringify(registers, null, 2));
        // Inspect the stack
        var stackPointer = context.sp;
        console.log('Stack pointer:', stackPointer);
}

function handleError(ret, context, syscallName) {
        if (ret === -1) {
                var errno = errnoFuncC().readInt();
                console.log(`errno in ${syscallName} `, errno);
                context.rax = -1;
                context.rbx = 0;
                context.rcx = errno;
        }
}

let isPrepRegsFunctionAttached = "NULL";
let isPrepRegs6FunctionAttached = "NULL";

Interceptor.replace(originalSocket, prepRegsFunction);
Interceptor.replace(originalBind, prepRegsFunction);
Interceptor.replace(originalListen, prepRegsFunction);
Interceptor.replace(originalGetSockName, prepRegsFunction);
Interceptor.replace(originalSetSockOpt, prepRegs6Function);
// Interceptor.replace(originalAccept4, prepRegs6Function);
Interceptor.replace(originalGetSockOpt, prepRegs6Function);
Interceptor.replace(originalConnect, prepRegsFunction);

/* Interception of socket() call */
Interceptor.attach(originalSocket, {
        onEnter: function() {                       
                isPrepRegsFunctionAttached = "socket";
                console.log('Intercepted originalSocket call');
                inspectContext(this.context);               
        },
        onLeave: function(retval) {
                isPrepRegsFunctionAttached = "NULL";
                console.log('originalSocket return value:', retval.toInt32());
                inspectContext(this.context);
        }    
});

/* Interception of bind() call */
Interceptor.attach(originalBind, {
        onEnter: function() {
                isPrepRegsFunctionAttached = "bind";
                console.log('Intercepted originalBind call');
                inspectContext(this.context);
        },
        onLeave: function(retval) {
                isPrepRegsFunctionAttached = "NULL";
                console.log('originalBind return value:', retval.toInt32());
                inspectContext(this.context);
        }    
});

/* Interception of listen() call */
Interceptor.attach(originalListen, {
        onEnter: function() {
                isPrepRegsFunctionAttached = "listen";
                console.log('Intercepted originalListen call');
                inspectContext(this.context);
        },
        onLeave: function(retval) {
                isPrepRegsFunctionAttached = "NULL";
                console.log('originalListen return value:', retval.toInt32());
                inspectContext(this.context);
        }    
});

/* Interception of getsockname() call */
Interceptor.attach(originalGetSockName, {
        onEnter: function() {
                isPrepRegsFunctionAttached = "getsockname";
                console.log('Intercepted originalGetSockName call');
                inspectContext(this.context);
        },
        onLeave: function(retval) {
                isPrepRegsFunctionAttached = "NULL";
                console.log('originalGetSockName return value:', retval.toInt32());
                inspectContext(this.context);
        }    
});

/* Interception of setsockopt() call */
Interceptor.attach(originalSetSockOpt, {
        onEnter: function() {
                isPrepRegs6FunctionAttached = "setsockopt";
                console.log('Intercepted originalSetSockOpt call');
                inspectContext(this.context);
        },
        onLeave: function(retval) {
                isPrepRegs6FunctionAttached = "NULL";
                console.log('originalSetSockOpt return value:', retval.toInt32());
                inspectContext(this.context);
        }    
});

/* Interception of accept4() call */
// Interceptor.attach(originalAccept4, {
//         onEnter: function() {
//                 isPrepRegs6FunctionAttached = "accept4";
//                 console.log('Intercepted originalAccept4 call');
//                 inspectContext(this.context);
//         },
//         onLeave: function(retval) {
//                 isPrepRegs6FunctionAttached = "NULL";
//                 console.log('originalAccept4 return value:', retval.toInt32());
//                 inspectContext(this.context);                
//         }    
// });

/* Interception of getsockopt() call */
Interceptor.attach(originalGetSockOpt, {
        onEnter: function() {
                isPrepRegs6FunctionAttached = "getsockopt";
                console.log('Intercepted originalGetSockOpt call');
                inspectContext(this.context);
        },
        onLeave: function(retval) {
                isPrepRegs6FunctionAttached = "NULL";
                console.log('originalGetSockOpt return value:', retval.toInt32());
                inspectContext(this.context);
        }    
});

/* Interception of connect() call */
Interceptor.attach(originalConnect, {
        onEnter: function() {
                isPrepRegsFunctionAttached = "connect";
                console.log('Intercepted originalConnect call');
                inspectContext(this.context);
        },
        onLeave: function(retval) {
                isPrepRegsFunctionAttached = "NULL";
                console.log('originalConnect return value:', retval.toInt32());
                inspectContext(this.context);
                // intentionally added to stop stop execution for debugging
                send('Pausing execution. Inspect registers.');
                recv('resume', function(value) {
                        console.log('Resuming execution.');
                }).wait();                 
        }    
});

Interceptor.attach(prepRegsFunction, {
        onEnter: function() {
                console.log('Intercepted prepRegsFunction call');
                inspectContext(this.context)
        },
        onLeave: function(retval) {
                // call the ldpSocketFunction
                if (isPrepRegsFunctionAttached === "socket") {
                        console.log('prepRegsFunction OnLeave calling ldpSocketFunction');
                        inspectContext(this.context);
                        var ret = ldpSocketFunction(this.context.rdi.toInt32(), this.context.rsi.toInt32(), this.context.rdx.toInt32());
                        console.log('ldpSocketFunction returned ', ret);
                        handleError(ret, this.context, "socket");
                        // replace the return value since we call this from prepRegsFunction but we want to return the value from ldpSocketFunction
                        retval.replace(ret);

                // call the ldpBindFunction
                } else if (isPrepRegsFunctionAttached === "bind") {
                        console.log('prepRegsFunction OnLeave calling ldpBindFunction');
                        inspectContext(this.context);            
                        // call the ldpBindFunction
                        var ret = ldpBindFunction(this.context.rdi.toInt32(), this.context.rsi, this.context.rdx.toInt32());
                        console.log('ldpBindFunction returned ', ret);
                        handleError(ret, this.context, "bind");
                        // replace the return value since we call this from prepRegsFunction but we want to return the value from ldpBindFunction
                        retval.replace(ret);

                // call the ldpListenFunction
                } else if (isPrepRegsFunctionAttached === "listen") {
                        console.log('prepRegsFunction OnLeave calling ldpListenFunction');
                        inspectContext(this.context);
                        // call the ldpListenFunction
                        var ret = ldpListenFunction(this.context.rdi.toInt32(), this.context.rsi.toInt32());
                        console.log('ldpListenFunction returned ', ret);
                        handleError(ret, this.context, "listen");
                        // replace the return value since we call this from prepRegsFunction but we want to return the value from ldpListenFunction
                        retval.replace(ret);

                // call the ldpGetSockNameFunction
                } else if (isPrepRegsFunctionAttached === "getsockname") {
                        console.log('prepRegsFunction OnLeave calling ldpGetSockNameFunction');
                        inspectContext(this.context);
                        // call the ldpGetSockNameFunction
                        var ret = ldpGetSockNameFunction(this.context.rdi.toInt32(), this.context.rsi, this.context.rdx);
                        console.log('ldpGetSockNameFunction returned ', ret);
                        handleError(ret, this.context, "getsockname");
                        // replace the return value since we call this from prepRegsFunction but we want to return the value from ldpGetSockNameFunction
                        retval.replace(ret);

                // call the ldpConnectFunction
                } else if (isPrepRegsFunctionAttached === "connect") {                  
                        console.log('prepRegsFunction OnLeave calling ldpConnectFunction');
                        inspectContext(this.context);
                        // call the ldpConnectFunction
                        var ret = ldpConnectFunction(this.context.rdi.toInt32(), this.context.rsi, this.context.rdx.toInt32());
                        console.log('ldpConnectFunction returned ', ret);
                        handleError(ret, this.context, "connect");
                         // replace the return value since we call this from prepRegsFunction but we want to return the value from ldpConnectFunction
                        retval.replace(ret);
                }                
        }
});

Interceptor.attach(prepRegs6Function, {
        onEnter: function() {
                console.log('Intercepted prepRegs6Function call');
                inspectContext(this.context);
        },
        onLeave: function(retval) {
                // call the ldpSetSockOptFunction
                if (isPrepRegs6FunctionAttached === "setsockopt") {
                        console.log('prepRegs6Function OnLeave calling ldpSetSockOptFunction');
                        inspectContext(this.context);
                        // call the ldpSetSockOptFunction
                        var ret = ldpSetSockOptFunction(this.context.rdi.toInt32(), this.context.rsi.toInt32(), this.context.rdx.toInt32(), this.context.rcx, this.context.r8.toInt32());
                        console.log('ldpSetSockOptFunction returned ', ret);
                        handleError(ret, this.context, "setsockopt");
                        // replace the return value since we call this from prepRegs6Function but we want to return the value from ldpSetSockOptFunction
                        retval.replace(ret);

                // call the ldpAccept4Function
                } else if (isPrepRegs6FunctionAttached === "accept4") {
                        console.log('prepRegs6Function OnLeave calling ldpAccept4Function');
                        inspectContext(this.context);
                        // call the ldpAccept4Function
                        var ret = ldpAccept4Function(this.context.rdi.toInt32(), this.context.rsi, this.context.rdx, this.context.rcx.toInt32());
                        console.log('ldpAccept4Function returned ', ret);
                        handleError(ret, this.context, "accept4");
                        // replace the return value since we call this from prepRegsFunction but we want to return the value from ldpAccept4Function
                        retval.replace(ret);

                // call the ldpGetSockOptFunction
                } else if (isPrepRegs6FunctionAttached == "getsockopt") {
                        console.log('prepRegs6Function OnLeave calling ldpGetSockOptFunction');
                        inspectContext(this.context);
                        // call the ldpGetSockOptFunction
                        var ret = ldpGetSockOptFunction(this.context.rdi.toInt32(), this.context.rsi.toInt32(), this.context.rdx.toInt32(), this.context.rcx, this.context.r8);
                        console.log('ldpGetSockOptFunction returned ', ret);
                        handleError(ret, this.context, "getsockopt");
                        // replace the return value since we call this from prepRegsFunction but we want to return the value from ldpGetSockOptFunction
                        retval.replace(ret);
                }
        }    
});