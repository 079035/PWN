---
title: "LINE CTF '23 simple blogger"
style: border
color: success
comments: true
description: LINE CTF's cool pwn challenge
tags: Pwn
---

# Simple Blogger

Last week, I tried out two CTFs (Umass and LINE). The Umass CTF was kind of easy (solved pwn in 2nd place), I and wanted to challenge myself. So I took upon an attempt to solve a challenge from a CTF that is a bit more well known for its diffuculty, the LINE CTF.

Spoiler, I couldn't solve it in time; but this is a kind of a recap and a review note about things I learned along while solving this challenge.

## Analysis

The first impression of this challenge was a bit startling, as the files given looked very different from the usual files given at other CTFs.

It looked like:
```bash
> # ls
agent  client  docker-compose.yml  init.sql  server  start_server.sh  stop_server.sh
```

There are three folders: agent, client, and server, some scripts and Dockerfiles to deploy test environment.

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

It is creating three tables, blog, account, and sess respectively, and is storing contents such as user and pass, and session values.

Let's take a look at ```server```.
```bash
> # ls
Dockerfile  flag  nsjail  nsjail.cfg  server_nix  server_nix.i64  simple_blogger.db
```

I'm not super familiar with these config and db files, but what we really need to care about are the binaries.

```client``` also has a similar ```client_nix``` binary inside the folder that serves as a client program to connect to the server.
Finally, ```agent``` is a sort of an independent helper client that runs this Python sciprt as a cron job that refreshes the admin's session token every other period (admin_janitor.py):
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

It took me a bit to absorb the overall setup, and now I could be more comfortable when approaching similar problems in the future.
Now let's see the actual binaries we're going to exploit.
```server_nix```:
```c

