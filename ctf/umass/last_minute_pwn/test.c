#include <stdio.h>
#include <string.h>

int main() {
    FILE *stream; // [rsp+0h] [rbp-10h]
    char *s; // [rsp+8h] [rbp-8h]

    s = (char *)malloc(0x14uLL);
    stream = fopen("/dev/urandom", "rb");
    fgets(s, 16, stream);
    s[16] = 0;
    fclose(stream);
    printf("%s\n", s);
}