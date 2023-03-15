#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

int main()
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    char buf1[0x7];
    char buf2[0x7];

    int data = open("/dev/urandom", O_RDONLY);
    read(data, buf2, sizeof buf2);

    printf("input: ");

    gets(buf1);

    if(!strcmp(buf1, buf2)){
        system("/bin/sh");
    }
    else{
        exit(0);
    }
}