global wrapperFunction

section .text

wrapperFunction:
    ; Save all registers
    push rax
    push rbx
    push rcx
    push rdx
    push rdi
    push rsi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    ; Move RAX, RBX, RCX to RDI, RSI, RDX
    mov rdi, rax
    mov rsi, rbx
    mov rdx, rcx

    ; Call the function (address in RAX)
    call rax

    ; Error Handling
    cmp rax, 0xfffffffffffff001
    jbe ok
    neg rax
    mov rcx, rax  ; errno
    mov rax, -1   ; r1
    xor rbx, rbx  ; r2 (set to 0)
    jmp end

ok:
    ; Save return value
    mov [rsp - 8], rax

end:
    ; Restore all registers
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rsi
    pop rdi
    pop rdx
    pop rcx
    pop rbx
    pop rax

    ; Set return value in RAX
    mov rax, [rsp - 8]
    mov rbx, rdx  ; r2
    xor rcx, rcx  ; errno (set to 0)

    ret






















; NASM syntax
section .data
    msg db 'Hello World', 10    ; 10 is the ASCII code for newline
    msg_len equ $ - msg

section .text
global prepRegs

prepRegs:
    ; Prologue
    push rbp
    mov rbp, rsp

    ; Print "Hello World"
    mov rax, 1          ; syscall number for write
    mov rdi, 1          ; file descriptor 1 is stdout
    mov rsi, msg        ; address of string to output
    mov rdx, msg_len    ; number of bytes
    syscall

    ; Epilogue
    mov rsp, rbp
    pop rbp

    ret






; NASM syntax
section .text
global prepRegs

prepRegs:
    ; Prologue
    push rbx
    push r12
    push r13
    push r14

    ; Load function pointer (assuming it's passed in rdi)
    ; mov r12, rax

    ; Swap registers to match System V ABI
    mov rdi, rax
    mov rsi, rbx
    mov rdx, rcx

    ; Call the function
    ; call r12

    ; Check if return value is -1
    cmp rax, -1
    jne .ok

    ; Handle error case
    xor rbx, rbx  ; Set second return value to 0
    xor rcx, rcx  ; Set "errno" to 0
    jmp .restore

.ok:
    mov rbx, rdx  ; Set second return value
    xor rcx, rcx  ; Set "errno" to 0

.restore:
    ; Epilogue
    pop r14
    pop r13
    pop r12
    pop rbx

    ret