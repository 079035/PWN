#!/usr/bin/python3
from pwn import *
import angr
import sys
import claripy
context.log_level='debug'
context.arch='amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)

def exp():
    p=process('./flipjump')
    # gdb.attach(p)

    for _ in 69:
        sla("length: ", length)
        
        sla("code: ", payload)

        print(p.recvline()) # flip
        print(p.recvline()) # Correct
        
        sla("Play again? (Y/N)", "Y")

    p.interactive()

GOOD = "pbctf" # pbctf
BAD  = "Wrong"
BASE = 0x400000

def good_path(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return GOOD.encode() in stdout_output  
def bad_path(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return BAD.encode() in stdout_output 

def main(argv):
    # Create an Angr project.
    path_to_binary = "./flipjump"
    
    project = angr.Project(path_to_binary, main_opts={"base_addr": BASE})
    
    initial_state = project.factory.entry_state(
        add_options = { angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                        angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
    )
    
    simulation = project.factory.simgr(initial_state)

    # Explore the binary to attempt to find the address that prints "Correct!"
    # good_address = 0x0000000000001979 # puts(correct)
    # bad_address = 0x0000000000001960 # puts(wrong)
    # This function will keep executing until it finds a solution or try all possible symbols.
    # simulation.explore(find=good_address, avoid=bad_address)

    simulation.explore(find=good_path, avoid=bad_path)

    # Print the string that Angr wrote to stdin to get solution_state.
    # This is our solution.
    if simulation.found:
        print("Solution: {%s}" %simulation.found[0].posix.dumps(sys.stdin.fileno()))
    else:
        raise Exception("Could not find the solution")

if __name__ == "__main__":
    main(sys.argv)

# p = process("./flipjump")
# sla("length:\n", b'l\xf1\xff?\xff\xff\xff\xff\xcf\xf0\xff?\xff\xff\xff\xff')
