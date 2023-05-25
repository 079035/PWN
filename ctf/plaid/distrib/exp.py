#!/usr/bin/python3
from pwn import *
from binascii import hexlify
context.log_level='debug'
context.arch='i386'
#context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

p=process(['wine','./baby-heap-question-mark.exe'])

ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)
# gdb.attach(p)


p.interactive()
