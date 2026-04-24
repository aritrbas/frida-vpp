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

const MODULE_NAME2 = '/usr/lib/libPrepRegs.so';

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

// Main execution
if (!checkLibraryLoaded2()) {
        loadLibrary2();
}

// Replace with the actual addresses or names of the functions
const originalSocket = syscallAddresses['syscall.socket'];
const originalSetSockOpt = syscallAddresses['syscall.setsockopt'];
// const wrapperFunc = new NativeFunction(Module.findExportByName('/usr/lib/libPrepRegs.so', 'prepRegs'), 'int', ['pointer']);
const prepRegsAddress = Module.findExportByName('/usr/lib/libPrepRegs.so', 'prepRegs');
const prepRegsFunction = new NativeFunction(prepRegsAddress, 'void', []);
const prepRegs6Address = Module.findExportByName('/usr/lib/libPrepRegs.so', 'prepRegs6');
const prepRegs6Function = new NativeFunction(prepRegs6Address, 'void', []);
const ldpSocketAddress = Module.findExportByName('/usr/lib/libvcl_ldpreload.so', 'socket');
const ldpSocketFunction = new NativeFunction(ldpSocketAddress, 'int', ['int', 'int', 'int']);
const ldpSetSockOptAddress = Module.findExportByName('/usr/lib/libvcl_ldpreload.so', 'setsockopt');
const ldpSetSockOptFunction = new NativeFunction(ldpSocketAddress, 'int', ['int', 'int', 'int', 'pointer', 'int']);

console.log(`prepRegsAddress: ${prepRegsAddress}`);
console.log(`prepRegs6Address: ${prepRegs6Address}`);
console.log(`originalSocket address: ${originalSocket}`);
console.log(`ldpSocketAddress: ${ldpSocketAddress}`);
console.log(`originalSetSockOpt address: ${originalSetSockOpt}`);
console.log(`ldpSetSockOptAddress: ${ldpSetSockOptAddress}`);


if (originalSocket && prepRegsAddress && ldpSocketAddress) {
        // Interceptor.replace(originalSocket, new NativeCallback(function() {
        // var registers = this.context;
        // console.log('Registers:', JSON.stringify(registers, null, 2));
        // return 0;
        // const result = wrapperFunction(vclSocket);
        // console.log("Result from replacement function:", result);

        // // Return the result from the replacement function
        // return result;
        // }, 'int', ['int', 'int', 'int'])); // Adjust return type and argument types as needed

        // Interceptor.replace(originalSocket, new NativeCallback(function(domain, type, protocol) {
        //         var registers = this.context;
        //         console.log('Registers:', JSON.stringify(registers, null, 2));
        //         console.log(`TEST Socket called with domain: ${domain}, type: ${type}, protocol: ${protocol}`);
        //         // Always return 0 without calling the original socket function
        //     }, 'int', ['int', 'int', 'int']));

        Interceptor.replace(originalSocket, prepRegsFunction);

        Interceptor.attach(originalSocket, {
                onEnter: function() {
                        console.log('Intercepted originalSocket call');
                        // Inspect the registers
                        var registers = this.context;
                        console.log('Registers:', JSON.stringify(registers, null, 2));
                        // Inspect the stack
                        var stackPointer = this.context.sp;
                        console.log('Stack pointer:', stackPointer);
                },
                onLeave: function(retval) {
                        console.log('originalSocket return value:', retval.toInt32());
                        var registers = this.context;
                        console.log('Registers:', JSON.stringify(registers, null, 2));

                        // // Example of stopping execution for inspection (blocking)
                        // send('Pausing execution. Inspect registers.');
                        // recv('resume', function(value) {
                        //         console.log('Resuming execution.');
                        // }).wait();                                            
                }    
                });
  
        Interceptor.attach(prepRegsFunction, {
                onEnter: function() {
                        console.log('Intercepted prepRegsFunction call');
                        // Inspect the registers
                        var registers = this.context;
                        console.log('Registers:', JSON.stringify(registers, null, 2));

                        // Inspect the stack
                        var stackPointer = this.context.sp;
                        console.log('Stack pointer:', stackPointer);
                },
                onLeave: function(retval) {
                        console.log('prepRegsFunction OnLeave calling ldpSocketFunction');
                        var registers = this.context;
                        console.log('Registers:', JSON.stringify(registers, null, 2));
                        var stackPointer = this.context.sp;
                        console.log('Stack pointer:', stackPointer);                        

                        var ret = ldpSocketFunction(this.context.rdi.toInt32(), this.context.rsi.toInt32(), this.context.rdx.toInt32());
                        console.log('ldpSocketFunction returned in var', ret);
                        retval.replace(ret);
                }    
                });       

        // // Approach 1 (replace Go func with ldp func)
        // /*
        //         causing "fatal error: runtime: split stack overflow" error
        //         irrespective of whether I try to modify the registers or not
        // */
        // // Interceptor.replace(originalSocket, ldp_socket);
        // Interceptor.attach(ldp_socket, {
        //         onEnter: function() {
        //                 console.log('Intercepted ldp_socket call');                                
        //                 // Inspect the registers
        //                 var registers = this.context;
        //                 console.log('Registers:', JSON.stringify(registers, null, 2));
        //                 var stackPointer = this.context.sp;
        //                 console.log('Stack pointer:', stackPointer);
        //         },
        //         onLeave: function(retval) {
        //                 console.log('ldp_socket return value:', retval.toInt32());
        //                 // Inspect the registers
        //                 var registers = this.context;
        //                 console.log('Registers:', JSON.stringify(registers, null, 2));
        //                 var stackPointer = this.context.sp;
        //                 console.log('Stack pointer:', stackPointer);
        //         }
        // });
        // Interceptor.attach(originalSocket, {
        //         onEnter: function() {
        //                 // Inspect the registers
        //                 console.log('Intercepted originalSocket call');                                
        //                 var registers = this.context;
        //                 console.log('Registers:', JSON.stringify(registers, null, 2));
        //                 var stackPointer = this.context.sp;
        //                 console.log('Stack pointer:', stackPointer);

        //                 console.log('Calling ldp_socket through wrapper func');                                
        //                 console.log(Process.enumerateModules());                        
        //                 console.log('wrapperFunc', wrapperFunc);
        //                 console.log('wrapperFunction', wrapperFunction);
        //                 console.log('vclSocket', vclSocket);                        
        //                 if (typeof wrapperFunc !== 'function') {
        //                         console.log('wrapperFunc is not a function:', wrapperFunc);
        //                 }
        //                 const result = wrapperFunc(vclSocket);
        //                 console.log('Result:', result);
        //                 console.log('Registers:', JSON.stringify(registers, null, 2));
        //                 var stackPointer = this.context.sp;                        

        //                 // console.log('Calling ldp_socket');                                
        //                 // const result = ldp_socket(vclSocket);
        //                 // console.log('Result:', result);
        //                 // console.log('Registers:', JSON.stringify(registers, null, 2));
        //                 // var stackPointer = this.context.sp;                        
        //         },
        //         onLeave: function(retval) {
        //                 console.log('originalSocket return value:', retval.toInt32());
        //                 // Inspect the registers
        //                 var registers = this.context;
        //                 console.log('Registers:', JSON.stringify(registers, null, 2));
        //                 var stackPointer = this.context.sp;
        //                 console.log('Stack pointer:', stackPointer);                                
        //         }
        // });
} else {
        console.log("Function(s) not found!");
}



if (originalSetSockOpt && prepRegs6Address && ldpSetSockOptAddress) {
        Interceptor.replace(originalSetSockOpt, prepRegs6Function);

        Interceptor.attach(originalSetSockOpt, {
                onEnter: function() {
                        console.log('Intercepted originalSetSockOpt call');
                        // Inspect the registers
                        var registers = this.context;
                        console.log('Registers:', JSON.stringify(registers, null, 2));
                        // Inspect the stack
                        var stackPointer = this.context.sp;
                        console.log('Stack pointer:', stackPointer);
                },
                onLeave: function(retval) {
                        console.log('originalSetSockOpt return value:', retval.toInt32());
                        var registers = this.context;
                        console.log('Registers:', JSON.stringify(registers, null, 2));

                        // Example of stopping execution for inspection (blocking)
                        send('Pausing execution. Inspect registers.');
                        recv('resume', function(value) {
                                console.log('Resuming execution.');
                        }).wait();                                            
                }    
                });
  
        Interceptor.attach(prepRegs6Function, {
                onEnter: function() {
                        console.log('Intercepted prepRegs6Function call');
                        // Inspect the registers
                        var registers = this.context;
                        console.log('Registers:', JSON.stringify(registers, null, 2));

                        // Inspect the stack
                        var stackPointer = this.context.sp;
                        console.log('Stack pointer:', stackPointer);
                },
                onLeave: function(retval) {
                        console.log('prepRegs6Function OnLeave calling ldpSetSockOptFunction');
                        var registers = this.context;
                        console.log('Registers:', JSON.stringify(registers, null, 2));
                        var stackPointer = this.context.sp;
                        console.log('Stack pointer:', stackPointer);                        

                        var ret = ldpSetSockOptFunction(this.context.rdi.toInt32(), this.context.rsi.toInt32(), this.context.rdx.toInt32(), this.context.rcx, this.context.r8.toInt32());
                        console.log('ldpSetSockOptFunction returned in var', ret);
                        retval.replace(ret);

                        prepRegs6Address();
                }    
                });
} else {
        console.log("Function(s) not found!");
}