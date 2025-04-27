.global _start

.section .text
_start:
    lea %rdi, [%rip + bin_sh]
    xor %rsi, %rsi
    xor %rdx, %rdx
    mov %rax, 0x3b
    syscall

bin_sh: .asciz "/bin/sh"
