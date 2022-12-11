echo "from pwn import *" > exp.py
echo "context.log_level='debug'" >> exp.py
echo "context.arch='amd64'" >> exp.py
echo "#context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']" >> exp.py
echo "p=process('./pwn')" >> exp.py
echo "ru 		= lambda a: 	p.readuntil(a)">> exp.py
echo "r 		= lambda n:		p.read(n)">> exp.py
echo "sla 	= lambda a,b: 	p.sendlineafter(a,b)">> exp.py
echo "sa 		= lambda a,b: 	p.sendafter(a,b)">> exp.py
echo "sl		= lambda a: 	p.sendline(a)">> exp.py
echo "s 		= lambda a: 	p.send(a)">> exp.py
echo "gdb.attach(p)">> exp.py
echo "p.interactive()">> exp.py
