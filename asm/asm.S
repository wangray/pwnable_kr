; PoC assembly code for nasm
; compile with 
; nasm -f elf64 asm.S 
; gcc asm.o -o test


section .data
    msg db      "flag.txt"

section .text
    global main
main:
    ; open syscall, args are 
    ; filename in rdi
    ; oflag in rsi 
    push 1
    push 0x7478742e
    push 0x67616c66
    mov     rax, 2 ; syscall number
    mov     rdi, msg 
    mov     rsi, 42
    syscall
    mov r10, rax ; return value of syscall

    ; read syscall, args are
    ; fd in rdi
    ; &buf in rsi 
    ; numBytes in rdx
    xor eax, eax ; syscall number
    push r10
    pop rdi 
    push 16
    pop rdx
    mov rsi, rsp
    syscall

    ; write syscall, args are
    ; fd in rdi (1 for stdout)
    ; &buf in rsi 
    ; numBytes in rdx
    push 1
    pop rax ;syscall number
    push 1
    pop rdi
    push 16
    pop rdx
    mov rsi, rsp
    syscall
    


