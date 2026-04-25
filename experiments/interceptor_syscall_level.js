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
const moduleName = 'echo_server';
const syscalls = ['syscall.socket', 'syscall.setsockopt', 'syscall.bind', 'syscall.Listen', 'syscall.getsockname', 'syscall.accept4', 'syscall.getsockopt', 'syscall.connect', 'syscall.Syscall', 'syscall.Syscall6', 'syscall.RawSyscall', 'syscall.RawSyscall6', 'runtime/internal/syscall.Syscall6', 'syscall.errnoErr'];

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

// // Main execution
// modules.forEach(moduleName => {
//         if (!checkLibraryLoaded(moduleName)) {
//                 loadLibrary(moduleName);
//         }
// });



// /* Logging for debugging */
// const prepRegsAddress = Module.findExportByName('/usr/lib/libPrepRegs.so', 'prepRegs');
// const prepRegsFunction = new NativeFunction(prepRegsAddress, 'void', []);

// const prepRegs6Address = Module.findExportByName('/usr/lib/libPrepRegs.so', 'prepRegs6');
// const prepRegs6Function = new NativeFunction(prepRegs6Address, 'void', []);

const originalSocket = syscallAddresses['syscall.socket'];
const ldpSocketAddress = Module.findExportByName('/usr/lib/libvcl_ldpreload.so', 'socket');
// const ldpSocketFunction = new NativeFunction(ldpSocketAddress, 'int', ['int', 'int', 'int']);

// const originalSetSockOpt = syscallAddresses['syscall.setsockopt'];
// const ldpSetSockOptAddress = Module.findExportByName('/usr/lib/libvcl_ldpreload.so', 'setsockopt');
// const ldpSetSockOptFunction = new NativeFunction(ldpSetSockOptAddress, 'int', ['int', 'int', 'int', 'pointer', 'int']);

// const originalBind = syscallAddresses['syscall.bind'];
// const ldpBindAddress = Module.findExportByName('/usr/lib/libvcl_ldpreload.so', 'bind');
// const ldpBindFunction = new NativeFunction(ldpBindAddress, 'int', ['int', 'pointer', 'int']);

// const originalListen = syscallAddresses['syscall.Listen'];
// const ldpListenAddress = Module.findExportByName('/usr/lib/libvcl_ldpreload.so', 'listen');
// const ldpListenFunction = new NativeFunction(ldpListenAddress, 'int', ['int', 'int']);

// const originalGetSockName = syscallAddresses['syscall.getsockname'];
// const ldpGetSockNameAddress = Module.findExportByName('/usr/lib/libvcl_ldpreload.so', 'getsockname');
// const ldpGetSockNameFunction = new NativeFunction(ldpGetSockNameAddress, 'int', ['int', 'pointer', 'pointer']);

// const originalAccept4 = syscallAddresses['syscall.accept4'];
// const ldpAccept4Address = Module.findExportByName('/usr/lib/libvcl_ldpreload.so', 'accept4');
// const ldpAccept4Function = new NativeFunction(ldpAccept4Address, 'int', ['int', 'pointer', 'pointer', 'int']);

/* Testing this approach */
const originalSyscall = syscallAddresses['syscall.Syscall'];
console.log(`originalSyscall address: ${originalSyscall}`);
const originalSyscall6 = syscallAddresses['syscall.Syscall6'];
console.log(`originalSyscall6 address: ${originalSyscall6}`);
const originalRawSyscall = syscallAddresses['syscall.RawSyscall'];
console.log(`originalRawSyscall address: ${originalRawSyscall}`);
const originalRawSyscall6 = syscallAddresses['syscall.RawSyscall6'];
console.log(`originalRawSyscall6 address: ${originalRawSyscall6}`);
const runtimeSyscall6 = syscallAddresses['runtime/internal/syscall.Syscall6'];
console.log(`runtime/internal/syscall.Syscall6 address: ${runtimeSyscall6}`);
const originalerrnoErr = syscallAddresses['syscall.errnoErr'];
console.log(`originalerrnoErr address: ${originalerrnoErr}`);

// console.log(`prepRegsAddress: ${prepRegsAddress}`);
// console.log(`prepRegs6Address: ${prepRegs6Address}`);

console.log(`originalSocket address: ${originalSocket}`);
console.log(`ldpSocketAddress: ${ldpSocketAddress}`);

// console.log(`originalSetSockOpt address: ${originalSetSockOpt}`);
// console.log(`ldpSetSockOptAddress: ${ldpSetSockOptAddress}`);

// console.log(`originalBind address: ${originalBind}`);
// console.log(`ldpBindAddress: ${ldpBindAddress}`);

// console.log(`originalListen address: ${originalListen}`);
// console.log(`ldpListenAddress: ${ldpListenAddress}`);

// console.log(`originalGetSockName address: ${originalGetSockName}`);
// console.log(`ldpGetSockNameAddress: ${ldpGetSockNameAddress}`);

// console.log(`originalAccept4 address: ${originalAccept4}`);
// console.log(`ldpAccept4Address: ${ldpAccept4Address}`);

function inspectContext(context) {
        // Inspect the registers
        var registers = context;
        console.log('Registers:', JSON.stringify(registers, null, 2));
        // Inspect the stack
        var stackPointer = context.sp;
        console.log('Stack pointer:', stackPointer);
}

function executeCodeRange(baseAddress) {
        var startAddress, endAddress;
    
        // Find the "test %rcx,%rcx" instruction
        var currentAddress = ptr(baseAddress);
        while (true) {
            var instruction = Instruction.parse(currentAddress);
            console.log('Instruction:', instruction);
            if (instruction.mnemonic === 'test' && 
                instruction.operands[0].value === 'rcx' && 
                instruction.operands[1].value === 'rcx') {
                startAddress = currentAddress;
                break;
            }
            currentAddress = instruction.next;
        }
    
        // Find the "add $0x<xyz>,%rsp" instruction
        currentAddress = startAddress;
        while (true) {
            var instruction = Instruction.parse(currentAddress);
            console.log('Instruction:', instruction);
            if (instruction.mnemonic === 'add' && 
                instruction.operands[0].value === 'rsp') {
                break;
            }
            endAddress = currentAddress;
            currentAddress = instruction.next;
        }
    
        console.log('Start address:', startAddress);
        console.log('End address:', endAddress);
    
        // Calculate the size of the code to execute
        var codeSize = endAddress.sub(startAddress).add(1);
    
        // // Allocate memory for our code
        // var codePtr = Memory.alloc(codeSize);
    
        // // Copy the original code to our allocated memory
        // Memory.copy(codePtr, startAddress, codeSize);
    
        // // Create a NativeFunction from our copied code
        // var func = new NativeFunction(codePtr, 'void', []);
    
        // // Execute the function
        // try {
        //     func();
        //     console.log('Code executed successfully');
        // } catch (error) {
        //     console.log('Error executing code:', error);
        // }

        // Log the disassembled instructions
        var instructions = [];
        var currentAddress = startAddress;

        while (currentAddress.compare(endAddress) <= 0) {
        try {
                var instruction = Instruction.parse(currentAddress);
                instructions.push(instruction);
                currentAddress = instruction.next;
        } catch (error) {
                console.log('Error parsing instruction at', currentAddress, ':', error);
                break;
        }
        }

        // Log the disassembled instructions
        console.log('Disassembled instructions:');
        instructions.forEach(function(instr, index) {
        console.log(
                index + ': ' +
                instr.address + ' - ' +
                instr.mnemonic + ' ' +
                instr.opStr
        );
        });        
}
    
/* Interception of RawSyscall6 call */
// if (originalRawSyscall6) {

        // Interceptor.replace(originalRawSyscall6, prepRegsFunction);

        // Interceptor.attach(prepRegsFunction, {
        //         onEnter: function() {
        //                 console.log('Intercepted prepRegsFunction call');
        //                 inspectContext(this.context)
        //                 // intentionally added to stop stop execution for debugging
        //                 send('Pausing execution. Inspect registers.');
        //                 recv('resume', function(value) {
        //                         console.log('Resuming execution.');
        //                 }).wait();                        
        //         },
        //         onLeave: function(retval) {
        //                 console.log('prepRegsFunction return value:', retval.toInt32());
        //                 var registers = this.context;
        //                 console.log('Registers:', JSON.stringify(registers, null, 2));
                        
        //                 var ret = -123;
        //                 switch (this.context.r10.toInt32()) {
        //                                 case 41:
        //                                                 ret = ldpSocketFunction(this.context.rdi.toInt32(), this.context.rsi.toInt32(), this.context.rdx.toInt32());
        //                                                 break;
        //                                 case 54:
        //                                                 ret = ldpSetSockOptFunction(this.context.rdi.toInt32(), this.context.rsi.toInt32(), this.context.rdx.toInt32(), this.context.rcx, this.context.r8.toInt32());
        //                                                 break;
        //                                 case 49:
        //                                                 ret = ldpBindFunction(this.context.rdi.toInt32(), this.context.rsi, this.context.rdx.toInt32());
        //                                                 break;
        //                                 case 50:
        //                                                 ret = ldpListenFunction(this.context.rdi.toInt32(), this.context.rsi.toInt32());
        //                                                 break;
        //                                 case 51:
        //                                                 ret = ldpGetSockNameFunction(this.context.rdi.toInt32(), this.context.rsi, this.context.rdx);
        //                                                 break;
        //                                 case 288:
        //                                                 ret = ldpAccept4Function(this.context.rdi.toInt32(), this.context.rsi, this.context.rdx, this.context.rcx.toInt32());
        //                                                 break;
        //                                 default:
        //                                                 console.log('Unknown syscall number in r10:', this.context.r10.toInt32());
        //                 }
        //                 console.log('ldpFunction returned ', ret);
        //                 // replace the return value since we call this from prepRegsFunction but we want to return the value from ldpSocketFunction
        //                 retval.replace(ret);
        //                 // // intentionally added to stop stop execution for debugging
        //                 // send('Pausing execution. Inspect registers.');
        //                 // recv('resume', function(value) {
        //                 //         console.log('Resuming execution.');
        //                 // }).wait();                         
        //         }    
        // });

// Interceptor.attach(runtimeSyscall6, {
//         onEnter(args) {
//             const threadId = this.threadId;
//             console.log('Function called, printing backtrace:');
        
//             // Get the backtrace
//             var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
//                 .map(DebugSymbol.fromAddress)
//                 .join('\n');
            
//             console.log(backtrace);

//         //     console.log('Entering syscall6, following thread:', threadId);
            
//         //     Stalker.follow(threadId, {
//         //         events: {
//         //             call: true,  // Trace calls
//         //             ret: true,   // Trace returns
//         //             exec: true   // Trace all instructions
//         //         },
//         //         onReceive(events) {
//         //             const parsed = Stalker.parse(events);
//         //             for (const event of parsed) {
//         //                 console.log('Stalker event:', JSON.stringify(event));
//         //             }
//         //         },
//         //         transform(iterator) {
//         //             let instruction;
//         //             while ((instruction = iterator.next()) !== null) {
//         //                 console.log('Instruction:', instruction);
//         //                 iterator.keep();
//         //             }
//         //         }
//         //     });
//         },
//         onLeave(retval) {
//             console.log('Leaving syscall6, stopping Stalker');
//             Stalker.unfollow(this.threadId);
//         }
//     });

// Interceptor.attach(originalSyscall, {
//         onEnter: function() {
//                 console.log(this.context.rax.toInt32());
//         }
// });

// Interceptor.attach(originalSyscall6, {
//         onEnter: function() {
//                 console.log(this.context.rax.toInt32());
//         }
// });

// Interceptor.attach(originalRawSyscall, {
//         onEnter: function() {
//                 console.log(this.context.rax.toInt32());
//         }
// });

Interceptor.attach(originalSocket, {
        onEnter: function() {
                console.log(this.context.rax.toInt32());
                executeCodeRange(originalSocket);
        }
});

// Interceptor.attach(originalRawSyscall6, function(args) {
//                 console.log(this.context.rax.toInt32());
//                 // inspectContext(this.context);
// });     