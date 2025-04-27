from sys import argv

if len(argv) != 2:
    print(f"Usage: {argv[0]} <shellcode path>")
    exit(1)

with open(argv[1], "rb") as f:
    content = f.read()
    content_len = len(content)
    content_set = set(content)
    content_set_len = len(content_set)
    print(f"Number of different bytes: {content_set_len}")
    print(f"Shellcode len: {content_len}")
    if content_set_len <= 6 and content_len < 0x80:
        print(content.hex())
