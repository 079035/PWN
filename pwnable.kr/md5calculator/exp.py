#!/usr/bin/python3
from pwn import *

context.log_level = "debug"
context.arch = "i386"
context.terminal = ["tmux", "splitw", "-h", "-F" "#{pane_pid}", "-P"]
# p=process('./hash')
e = ELF("./hash")
libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
p = remote("pwnable.kr", 9002)
ru = lambda a: p.readuntil(a)
r = lambda n: p.read(n)
sla = lambda a, b: p.sendlineafter(a, b)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
s = lambda a: p.send(a)

gdb.attach(p)

ru(": ")
captcha = p.recvline().decode()
sl(captcha)


p.interactive()
