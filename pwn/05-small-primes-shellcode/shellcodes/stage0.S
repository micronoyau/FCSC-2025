.global _start

.section .text
_start:
    // Nasty trick to do a "mov x8, 0x3f"
    mov x5, 0x3f
    stp x5, x2, [sp]
    ldp x11, x8, [sp, -0x8]

    // Nasty trick to do a "ldr x1, [sp, 0x20]" (buf is at [sp + 0x30 - 0x10])
    ldr x13, [sp, 0x20]
    stp x13, x6, [sp]
    ldp x1, x9, [sp]

    // Nasty trick to do a "mov x2, 0x202"
    mov x3, 0x202
    stp x3, x2, [sp]
    ldp x23, x2, [sp, -0x8]

    // Nasty trick to do a "mov x0, xzr"
    stp xzr, x10, [sp]
    ldp x7, x0, [sp, -0x8]

    // Put 0x13 to have a prime number (immediate is ignored)
    svc 0x13
