### RELRO
1.  find pop rdi; ret
2.  leak addr of function to overwrite
3.  calculate *base* using leak - libc.symbols['leak']
4.  calculate system using base + libc.symbols['system']
5.  find /bin/sh using base + next(libc.search('/bin/sh'))
