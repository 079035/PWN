import hashlib
import ecdsa
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import *

# Given values
s = 98064531907276862129345013436610988187051831712632166876574510656675679745081
r = 9821122129422509893435671316433203251343263825232865092134497361752993786340
cipher = b'\xf3#\xff\x17\xdf\xbb\xc0\xc6v\x1bg\xc7\x8a6\xf2\xdf~\x12\xd8]\xc5\x02Ot\x99\x9f\xf7\xf3\x98\xbc\x045\x08\xfb\xce1@e\xbcg[I\xd1\xbf\xf8\xea\n-'

msg = b'welcome to n1ctf2023!'
msg_hash = bytes_to_long(hashlib.sha256(msg).digest())
msg_bits = bin(msg_hash)[2:].zfill(256)[:128]

curve = ecdsa.NIST256p
G = curve.generator
order = curve.order

# Find k that fits both the nonce generation method and the ECDSA equation
for i in range(2**128):
    d_bits = bin(i)[2:].zfill(128)
    k_candidate = int(msg_bits + d_bits, 2)
    if (k_candidate * G).x() % order == r:
        k = k_candidate
        break

# Compute d using the derived k
s_inv = pow(s, -1, order)
z = msg_hash
d = ((s * k - z) * pow(r, -1, order)) % order

aes = AES.new(long_to_bytes(d), mode=AES.MODE_ECB)
decrypted = unpad(aes.decrypt(cipher), 16)

print(decrypted.decode())
