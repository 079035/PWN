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