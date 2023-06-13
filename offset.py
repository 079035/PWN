#!/usr/bin/python3
from pwn import *
from base64 import *
from ctypes import CDLL


#2.23_x86
system = libc.address + 0x3adb0
libc = libc.address + 0x15bb2b