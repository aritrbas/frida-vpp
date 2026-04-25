; NASM syntax
section .text
global prepRegs
global prepRegs6
global prepRegs2
global prepRegs3
global prepRegs4
global prepRegs5
global prepRegs7

prepRegs:
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

prepRegs2:
        ; Swap registers to match System V ABI
        mov rdi, rax
        mov rsi, rbx
        mov rdx, rcx

        ; Reset the Go registers to 0
        xor rax, rax
        xor rbx, rbx
        xor rcx, rcx

        ret        

prepRegs3:
        ; Swap registers to match System V ABI
        mov rdi, rax
        mov rsi, rbx
        mov rdx, rcx

        ; Reset the Go registers to 0
        xor rax, rax
        xor rbx, rbx
        xor rcx, rcx

        ret

prepRegs4:
        ; Swap registers to match System V ABI
        mov rdi, rax
        mov rsi, rbx
        mov rdx, rcx

        ; Reset the Go registers to 0
        xor rax, rax
        xor rbx, rbx
        xor rcx, rcx

        ret

prepRegs5:
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

prepRegs7:
        ; Save r12 & r13 as it's a callee-saved register in System V ABI
        push r12
        push r13

        ; Use temporary registers to store original values
        mov r10, rdi  ; Store original rdi in r10
        mov r11, rsi  ; Store original rsi in r11
        mov r12, r8  ; Store original r8 in r12
        mov r13, r9  ; Store original r9 in r13

        ; Swap registers to match System V ABI
        mov rdi, rbx
        mov rsi, rcx
        mov rdx, r10  ; Restore original rdi from r10
        mov rcx, r11  ; Restore original rsi from r11
        mov r8, r12  ; Restore original r8 from r12
        mov r9, r13  ; Restore original r9 from r13

        ; Store the trap number in r10
        mov r10, rax

        ; Reset the Go registers to 0
        xor rax, rax
        xor rbx, rbx

        ; Restore r12 before returning
        pop r13
        pop r12

        ret

checkError:
        ; Compare rax with -1
        cmp rax, -1
        jne .noError

        ; If rax is -1, set rcx as the input parameter (errno)
        mov rcx, rdi

        ; Set rbx to 0
        xor rbx, rbx

        ret

.noError:
        ret