from pwn import *
context.log_level='debug'

try:
    p=process("./simple_bof")
    
    p.sendlineafter(": ", b"") # payload
    
    p.sendline(b"pwd")
    p.read()
    p.interactive()
except:
    pass
