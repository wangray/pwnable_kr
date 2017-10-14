from pwn import *
import base64

p = remote("pwnable.kr", 9005)

binary = p.recvuntil("hurry up!")

binary = binary.split("\n")[8]

with open ("aeg", 'wb') as f:
    f.write(base64.b64decode(binary))

print binary
