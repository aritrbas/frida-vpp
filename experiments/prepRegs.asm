; NASM syntax
section .text
global prepRegs
global prepRegs6
global updateRegs

prepRegs:
        endbr64

        ; Swap registers to match System V ABI
        mov rdi, rax
        mov rsi, rbx
        mov rdx, rcx

        ; Reset the Go registers to 0
        xor rax, rax
        xor rbx, rbx
        xor rcx, rcx

        ret

prepRegs6:
        ; Save r12 as it's a callee-saved register in System V ABI
        push r12

        ; Use temporary registers to store original values
        mov r10, rdi  ; Store original rdi in r10
        mov r11, rsi  ; Store original rsi in r11
        mov r12, r8  ; Store original r8 in r12

        ; Swap registers to match System V ABI
        mov rdi, rax
        mov rsi, rbx
        mov rdx, rcx
        mov rcx, r10  ; Restore original rdi from r10
        mov r8, r11  ; Restore original rsi from r11
        mov r9, r12  ; Restore original r8 from r12

        ; Reset the Go registers to 0
        xor rax, rax
        xor rbx, rbx

        ; Restore r12 before returning
        pop r12

        ret

updateRegs:
        ; Set rax is -1 (indicating an error)
        mov rax, -1

        ; Set rcx as the input parameter (errno)
        mov rcx, rdi

        ; Set rbx to 0
        xor rbx, rbx

        ret