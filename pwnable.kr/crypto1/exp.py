from pwn import * 
import hashlib
context.log_level='error'

found_cookie=''

def bf_attack(start,end,k):
    global found_cookie
    for i in range(start,end):
        p=remote('pwnable.kr',9006)
        p.recvuntil('Input your ID\n')
        p.sendline('a'*(end-i))
        p.recvuntil('Input your PW\n')
        p.sendline('')
        p.recvuntil('sending encrypted data (')
        found_enc_data=p.recv(32*k)
        p.recvall()
        p.close()
        f=0
        for c in '1234567890abcdefghijklmnopqrstuvwxyz-_':
            p=remote('pwnable.kr',9006)
            p.recvuntil('Input your ID\n')
            p.sendline('a'*(end-i))
            p.recvuntil('Input your PW\n')
            p.sendline('-'+found_cookie+c)
            p.recvuntil('sending encrypted data (')
            try_enc_data=p.recv(32*k)
            p.close()
            if found_enc_data==try_enc_data:
                #print 'found - ' + c
                found_cookie=found_cookie+c
                f=1
                break
        if f==0:
            break

bf_attack(0,13,1)
bf_attack(14,30,2)
bf_attack(31,47,3)
bf_attack(48,64,4)

print(found_cookie)
