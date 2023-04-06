#!/usr/bin/python3
from pwn import *
context.log_level='debug'
context.arch='riscv'
context.os='linux'
#context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
p=process('./smash-baby')
e=ELF('./smash-baby')
#p=remote("riscv_smash.quals2023-kah5Aiv9.satellitesabove.me",5300)

ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)

sla("Ticket please:\n", "ticket{uniform220345charlie4:GDy26WQaqFSOl_RBatsHjOVT2UwGLd1zneHrtPvzgVy9JMFLAdD_dDowog64U1W8gA}")

ru("Because I like you (and this is a baby's first type chall) here is something useful: ")
leak = r(4).decode()

sla("Exploit me!\n")

gdb.attach(p)
p.interactive()
