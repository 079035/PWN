---
title: "Perfect Blue CTF '23 flipjump1"
date: 2023-02-24 12:20:30 -0400
categories: Misc
---

# Flipjump 1
Today I am going to write a problem I encountered during the perfect blue ctf '23 and recap about things I learned.

I believe flipjump1 wasn't that hard to understand, but it required some bit of advanced reversing skills that come from experience in order to solve this challenge. That's where I got stuck, but I learned some important lessons.

## Analysis
```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  wrap *rand; // [rsp+8h] [rbp-38h] BYREF
  void *p1_board; // [rsp+10h] [rbp-30h]
  void *p2_board; // [rsp+18h] [rbp-28h]
  __int64 p1_result; // [rsp+20h] [rbp-20h]
  wrap *p2_result; // [rsp+28h] [rbp-18h]
  char buf[2]; // [rsp+36h] [rbp-Ah] BYREF
  unsigned __int64 v10; // [rsp+38h] [rbp-8h]

  v10 = __readfsqword(0x28u);
  setup(argc, argv, envp);
  puts("Let's play a 2-player bit flip game using a bit flip VM.");
  p1_board = malloc(2uLL);
  p2_board = malloc(2uLL);
  memset(p1_board, 0, 2uLL);
  memset(p2_board, 0, 2uLL);
  while ( 1 )
  {
    rand = randomize_board(p1_board);
    *p2_board = *p1_board;
    p1_result = run_player(&p1_code, p1_board, &rand);// rand value
    printf(
      "Flip[%ld] Bit %ld %c->%c\n",
      p1_result / 8,
      p1_result % 8,
      ((*(p2_board + p1_result / 8) >> (p1_result & 7)) & 1u) + 48,// original bit
      (!((*(p2_board + p1_result / 8) >> (p1_result & 7)) & 1) + 48));// flipped bit
    *(p2_board + p1_result / 8) ^= 1 << (p1_result & 7);
    p2_result = run_player(&p2_code, p2_board, 0LL);
    if ( p2_result != rand )
    {
      puts("Wrong");
      exit(1);
    }
    puts("Correct!");
    if ( ++win_count == 69 )
      print_flag1();
    puts("Play again? (Y/N)");
    read(0, buf, 2uLL);
    if ( buf[0] != 89 )
      break;
    free(*p1_code);
    free(*p2_code);
    free(p1_code);
    free(p2_code);
    p1_code = 0LL;
    p2_code = 0LL;
  }
  return 0;
}
```
Main is fairly simple, what we need to take a keen look at are the calls to randomized_board and run_player.

Main calls run_player for player1, does some bit operations, calls run_player for player2, and compares the result of run_player of player2 and the result of randomized_board.

We need to make those equal 69 times in order to print flag.

Let's take a look at randomized_board.
```
__int64 __fastcall randomize_board(void *a1)
{
  __int64 v2[2]; // [rsp+10h] [rbp-10h] BYREF

  v2[1] = __readfsqword(0x28u);
  read(urandom_fd, a1, 2uLL);
  v2[0] = 0LL;
  read(urandom_fd, v2, 4uLL);
  return v2[0] % 16;
}
```
randomize_board makes a two byte table and returns a random integer in the range [0, 15].

run_player:
```
__int64 __fastcall run_player(void ***a1, __int64 a2, _QWORD *a3)
{
  void **v3; // rbx
  int j; // [rsp+20h] [rbp-20h]
  int v7; // [rsp+24h] [rbp-1Ch]
  __int64 i; // [rsp+28h] [rbp-18h]

  *a1 = (void **)malloc(0x18uLL);
  puts("Enter code length:");
  read(0, *a1 + 1, 8uLL);
  v3 = *a1;
  *v3 = malloc((size_t)(*a1)[1]);
  if ( !**a1 )
    exit(1);
  memset(**a1, 0, (size_t)(*a1)[1]);
  puts("Enter code:");
  for ( i = 0LL; i < (__int64)(*a1)[1]; i += v7 )
  {
    v7 = read(0, (char *)**a1 + 8 * (i / 8), (size_t)(*a1)[1] - i);
    if ( v7 < 0 )
      exit(1);
  }
  *((_DWORD *)*a1 + 4) = 0;
  for ( j = 0; j <= 15; ++j )
    *((_QWORD *)**a1 + 2 * j + (__int64)(*a1)[1] / 8 - 31) = ((*(char *)(j / 8 + a2) >> (j & 7)) & 1) != 0;
  if ( a3 )
    *((_QWORD *)**a1 + (__int64)(*a1)[1] / 8 - 33) = *a3;
  run_vm(*a1);
  return *((_QWORD *)**a1 + (__int64)(*a1)[1] / 8 - 33);
}
```
This part was quite hard to render in my mind with all the pointers. Later I found that a1 and a2 were essentially ```struct``` in c.

Since there are parts to enter the code length and the code, the structs might look like:
```
struct wrapper
{
  struct code_container *container;
};

struct code_container
{
  uint64_t *code;
  int64_t length;
  int32_t pc;
};
```
So a1 is essentially a wrapper to the actual code container.

I used [this](https://hshrzd.wordpress.com/2022/02/09/ida-tips-how-to-use-a-custom-structure/) to re-reverse the code using my custom struct.

The resulting run_player looks like:
```
wrap *__fastcall run_player(wrap *a1, __int64 board, _QWORD *rand)
{
  code_container *container; // rbx
  int j; // [rsp+20h] [rbp-20h]
  int v7; // [rsp+24h] [rbp-1Ch]
  int64_t i; // [rsp+28h] [rbp-18h]

  a1->container = malloc(0x18uLL);
  puts("Enter code length:");
  read(0, &a1->container->length, 8uLL);
  container = a1->container;
  container->code = malloc(a1->container->length);
  if ( !a1->container->code )
    exit(1);
  memset(a1->container->code, 0, a1->container->length);
  puts("Enter code:");
  for ( i = 0LL; i < a1->container->length; i += v7 )
  {
    v7 = read(0, &a1->container->code[i / 8], a1->container->length - i);
    if ( v7 < 0 )
      exit(1);
  }
  a1->container->pc = 0;
  for ( j = 0; j <= 15; ++j )
    a1->container->code[2 * j - 31 + a1->container->length / 8] = ((*(j / 8 + board) >> (j & 7)) & 1) != 0;
  if ( rand )
    a1->container->code[a1->container->length / 8 - 33] = *rand;
  run_vm(a1->container);
  return a1->container->code[a1->container->length / 8 - 33];
}
```
Now everything makes more sense.
run_player gets code length first, then gets the code, sets pc to 0, and will run the code using ```run_vm```.

I reversed a little bit of run_vm:
```
int64_t __fastcall run_vm(code_container *a1)
{
  int64_t len; // rax
  __int64 target; // rax
  int64_t current; // [rsp+10h] [rbp-10h]
  __int64 next; // [rsp+18h] [rbp-8h]

  while ( 1 )
  {
    current = a1->code[2 * a1->pc];
    next = a1->code[2 * a1->pc + 1];
    len = 8 * a1->length;
    if ( current >= len )                       // end
      break;
    if ( current < 0 || current > 8 * a1->length )// check range
      exit(1);
    target = a1->code[2 * a1->pc];
    *(a1->code + (target >> 3)) ^= 1 << (current & 7);// flip
    if ( next < 0 || 2 * next + 1 >= a1->length )
      exit(1);
    a1->pc = next;                              // next
  }
  return len;
}
```

This is where the bit operations happen and my code will run.

The code's syntax is interesting since it will contain two component, current and next. So each piece of code will require two segments in order to run correctly.

```current``` will become ```next``` every loop and will flip bits where ```target``` is pointing.

## Planning
To exit run_vm immediately is simple if you study the code a little bit, which is to make current (where pc is pointing at) an absurd address so that it will break out of while loop at this line: ```if ( current >= len )```. So the code will remain untouched.

We can achieve this by:
```
sa(b"length:\n", p64(0x200))

payload = b""
payload += (p64(0x400*8)+p64(0)) * (0x200//0x10)

sa(b"code:\n", payload)
```
```sa()``` here is equivalent to ```p.sendafter()```.
Since current and next will be p64(0x400*8) and p64(0) respectively, run_vm will exit immediately (0x400\*8 >= 0x200\*8).

I was caught up with the big flip operation, but the trick is to think simple. Since run_player's return value for player1 is equivalent to rand if we exit run_vm immediately, all we need to make sure is the return value of the second player's run_player is also rand.

The main function gives us a hint, which prints which byte and bit of the player1's board it flipped. Using this, we can recover ```rand``` by calculating ```rand = flip_byte * 8 + flip_bit```.

The code would look like:
```
res = p.recvline().decode()
byte = int(res[5])
log.critical(str(byte))
bit = int(res[12:14].strip())
log.critical(str(bit))

rand = byte * 8 + bit
```

The return value of run_player is ```a1->container->code[a1->container->length / 8 - 33]```. If we supply rand to this index of player2's code and make the code remain untouched by exiting run_vm immediately, we will win.

Using rand, our second payload would be:
```
sa(b"length:\n", p64(0x200))

payload = b""
payload += (p64(0x400*8)+p64(rand)) * (0x200//0x10)

sa(b"code:\n", payload)
```

And we need to do this 69 times.

## Exploit
Now we only need to put things together,

the final exploit is this:
```
#!/usr/bin/python3
from pwn import *
context.log_level='debug'
context.arch='amd64'
# context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)

p=process('./flipjump')

for _ in range(69):
    sa(b"length:\n", p64(0x200))

    payload = b""
    payload += (p64(0x400*8)+p64(0)) * (0x200//0x10)

    sa(b"code:\n", payload)

    # Flip[0] Bit 5 1->0

    res = p.recvline().decode()
    byte = int(res[5])
    log.critical(str(byte))
    bit = int(res[12:14].strip())
    log.critical(str(bit))

    rand = byte * 8 + bit

    sa(b"length:\n", p64(0x200))

    payload = b""
    payload += (p64(0x400*8)+p64(rand)) * (0x200//0x10)

    sa(b"code:\n", payload)
    
    sla(b"N)", b"Y")
    
p.interactive()
```

## Conclusion
This was a pretty challenging puzzle for me, with a bunch of pointers and bit calculations thrown at me, I was confused for a very long time and 36 hours was certainly not enough for me to solve this.

But as I kept uncovering the problem, things started to make more sense and became straight forward. The important takeaway is that I also need to work on reversing skills along with my exploiting skills so that I won't always have to rely on my reversing teammate.

Thank you,

079
