global _start

section .text
_start:
    ; Your shellcode goes here
    mov rax, 60     ; syscall: exit
    mov rdi, 0      ; status: 0
    syscall