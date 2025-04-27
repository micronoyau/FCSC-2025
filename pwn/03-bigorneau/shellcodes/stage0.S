.global _start

.section .text
_start:
    push %rsp
    pop %rsi
    mov %dl, 0xf0
    syscall
