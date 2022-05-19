from pwn import *

r = remote('178.62.76.45', 31801)
r.recvuntil("> ")
r.sendline(b'2')
r.recvuntil(': ')
r.sendline(b'aaaa')
print(r.recvline())
print(r.recvline())
