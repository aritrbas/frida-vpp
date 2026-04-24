const syscallNumbers = {
        socket: 41, // replace with the actual syscall number if different
        bind: 49,
        listen: 50,
        accept: 288,
        setsockopt: 54, // replace with the actual syscall number if different
        getsockname: 51, // replace with the actual syscall number if different
};

const moduleName = 'test_server_go';
const syscalls = ['syscall.RawSyscall6'];

function setupInterceptor(name) {
        Module.enumerateSymbols(moduleName, {
                onMatch: function (exp) {
                        if (exp.name === name) {
                                console.log(`Found ${name} at address: ${exp.address}`);
                                Interceptor.attach(exp.address, {
                                        onEnter: function (args) {
                                                console.log(`${name} called`);
                                                for (let i = 0; i < 7; i++) { // Adjust based on expected argument count
                                                if (args[i] !== undefined) {
                                                        console.log(`Argument ${i}: ` + args[i]);
                                                } else {
                                                        break;
                                                }
                                                }                                                
                                                const syscallNumber = args[0].toInt32();
                                                console.log(`syscallNumber: ` + syscallNumber);
                                                switch (syscallNumber) {
                                                        case syscallNumbers.socket:
                                                                console.log('socket called');
                                                                break;
                                                        case syscallNumbers.bind:
                                                                console.log('bind called');
                                                                break;
                                                        case syscallNumbers.listen:
                                                                console.log('listen called');
                                                                break;
                                                        case syscallNumbers.accept:
                                                                console.log('accept called');
                                                                break;
                                                        case syscallNumbers.setsockopt:
                                                                console.log('setsockopt called');
                                                                break;
                                                        case syscallNumbers.getsockname:
                                                                console.log('getsockname called');
                                                                break;
                                                        default:
                                                                break;
                                                }
                                        },
                                        onLeave: function (retval) {
                                                console.log(`${name} returned: ${retval}`);
                                        }
                                });
                        }
                },
                onComplete: function () {
                        console.log(`Finished enumerating exports for ${moduleName}`);
                }
        });
}

// Set up interceptors for all specified syscalls
syscalls.forEach(setupInterceptor);


// // Find the addresses of multiple syscalls
// const moduleName = 'test_server_go';
// const syscalls = ['syscall.socket', 'syscall.setsockopt', 'syscall.bind', 'syscall.Listen', 'syscall.getsockname'];

// // Function to set up an interceptor for a given syscall
// function setupInterceptor(name) {
//     Module.enumerateSymbols(moduleName, {
//         onMatch: function (exp) {
//             if (exp.name === name) {
//                 console.log(`Found ${name} at address: ${exp.address}`);
//                 Interceptor.attach(exp.address, {
//                     onEnter: function (args) {
//                         console.log(`${name} called`);
//                         console.log('rax : ' + this.context.rax);
//                         console.log('rbx : ' + this.context.rbx);
//                         console.log('rcx : ' + this.context.rcx);
//                         console.log('rdi: ' + this.context.rdi);
//                         console.log('rsi : ' + this.context.rsi);
//                         console.log('r8 : ' + this.context.r8);
//                         console.log('r9 : ' + this.context.r9);
//                         console.log('r10 : ' + this.context.r10);
//                         console.log('r11 : ' + this.context.r11);
//                         // for (let i = 0; i < 5; i++) { // Adjust based on expected argument count
//                         // if (args[i] !== undefined) {
//                         //         console.log(`Argument ${i}: ` + args[i]);
//                         // } else {
//                         //         break;
//                         // }
//                         // }
//                     },
//                     onLeave: function (retval) {
//                         console.log(`${name} returned: ${retval}`);
//                     }
//                 });
//             }
//         },
//         onComplete: function () {
//             console.log(`Finished enumerating exports for ${moduleName}`);
//         }
//     });
// }

// // Set up interceptors for all specified syscalls
// syscalls.forEach(setupInterceptor);
