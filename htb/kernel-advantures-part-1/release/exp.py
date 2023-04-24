#!/usr/bin/python3
from pwn import *
import os
context.log_level='debug'
context.arch='amd64'
#context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
# p=process('./pwn')
ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)
# gdb.attach(p)

os.system("x86_64-linux-musl-gcc exploit.c -o exploit -s -static -lpthread")
os.system("mv exploit rootfs/")
os.system("cd rootfs/; find .|cpio -o --format=newc > ../rootfs.cpio")
os.system("cd ..; gzip rootfs.cpio")


p.interactive()
