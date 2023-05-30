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

r='Timeout!'
while(r=='Timeout!' or "Slow down" in r):
    p=remote("welcome-to-quals-vfnva65rlchqk.shellweplayaga.me",10001)
    sla(": ", "ticket{LoftBroker938n23:UwulEbFkcGk2pIZfqmLHKs7151S3CkuqOzE87GaQwv9e_ULj}")
    r = p.recvline().decode().strip()
    sleep(1)

log.critical(r)
# p.sendline("yf /")
p.sendline(b"png /jrypbzr_synt.gkg")
p.interactive()
