#include "textflag.h"

// func prepRegs(fn uintptr) int64
TEXT ·prepRegs(SB),NOSPLIT,$32-16
    // Save callee-saved registers
    MOVQ BX, 0(SP)
    MOVQ R12, 8(SP)
    MOVQ R13, 16(SP)
    MOVQ R14, 24(SP)

    // Load function pointer
    MOVQ fn+0(FP), R12          // Function pointer

    // Swap registers to match System V ABI
    MOVQ AX, DI                 // RAX to RDI
    MOVQ BX, SI                 // RBX to RSI
    MOVQ CX, DX                 // RCX to RDX

    // Call the function
    CALL R12

    // Check if return value is -1
    CMPQ $-1, RAX               // Compare the return value with -1
    JNE ok                      // Jump to ok if return value is not -1

    // Handle the error case
    // RAX already contains -1
    MOVQ $0, BX    // Set second return value to 0
    MOVQ $0, CX   // Set errno to 0 (libc syscall stores it in thread specific storage - how do I get it?)
    JMP restore          // Jump to restore

ok:
    // RAX already contains the original return value from the syscall
    MOVQ DX, BX    // Set r2 (second return value)
    MOVQ $0, CX    // Set errno to 0

restore:
    // Restore callee-saved registers
    MOVQ 0(SP), BX
    MOVQ 8(SP), R12
    MOVQ 16(SP), R13
    MOVQ 24(SP), R14

    RET
