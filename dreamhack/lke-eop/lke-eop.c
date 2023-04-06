/* Copyright (C) 2020  Theori Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

/* pr_info() 등에서 사용할 커널 메시지 포맷을 정의합니다. */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>  /* 리눅스 커널 타입 및 매크로 */
#include <linux/module.h>  /* 모듈 관련 타입 및 매크로 */
#include <linux/cred.h>    /* prepare_kernel_cred, commit_creds */
#include <linux/proc_fs.h> /* proc_create, file_operations, ... */


/* 사용자 모드 프로세스가 /proc/lke-eop 파일에 쓰기 요청을
 * 보낼 때 이를 처리하기 위해 호출되는 함수입니다.
 *
 * @file:  쓰기 요청을 받은 FD의 파일 디스크립션을 나타내는 구조체입니다.
 * @buf:   파일에 쓰고자 하는 데이터를 저장하는 버퍼의 주소입니다.
 *         사용자 주소공간에 위치한 주소이며,
 *         직접 접근하는 대신 반드시 copy_from_user와 같은 함수를 사용하여
 *         먼저 커널 영역으로 복사한 후 사용하여야 합니다.
 * @count: 파일에 쓰고자 하는 데이터의 바이트 단위 크기입니다.
 * @ppos:  데이터가 씌어질 파일 내 위치를 저장하는 변수를 가리키는 포인터입니다.
 *         작업 완료 후 *ppos를 복사된 바이트수만큼 증가시키면,
 *         다음 write 호출에서 업데이트된 *ppos값이 다시 입력됩니다.
 *
 * 리턴값: 성공 시, 쓰여진 바이트 수를 반환합니다.
 *         실패 시, 음수 errno 값을 반환합니다. (예: -EIO)
 */
static ssize_t eop_write(struct file *file, const char __user *buf,
			 size_t count, loff_t *ppos)
{
	/* 권한 상승 코드를 실행합니다. */
	commit_creds(prepare_kernel_cred(NULL));

	/* 작업이 성공했음을 나타냅니다. */
	return count;

	/* 이외 인자는 모두 무시됩니다. 따라서 /proc/lke-eop 파일에
	 * 어떤 데이터를 쓰든지 권한상승이 발생합니다. */
}

/* /proc/lke-eop 파일 정보를 저장합니다. 모듈 언로드 시 사용됩니다. */
static struct proc_dir_entry *proc_eop;

/* 파일을 정의할 때, 가능한 작업들에 대한 구현을 저장하는 구조체입니다. */
static const struct file_operations eop_fops = {
	/* 소유자 커널 모듈을 나타내어, 파일이 열려 있는 동안에는
	 * 모듈 탈착(unload)을 할 수 없도록 합니다. */
	.owner = THIS_MODULE,

	/* 파일 쓰기를 구현하는 함수의 포인터를 지정합니다.
	 * 해당 파일에 write() 시스템 콜이 실행되면 이 함수가 호출됩니다. */
	.write = eop_write,
};

/* 모듈 부착(load) 시 호출되는 함수입니다. */
int __init init_module(void)
{
	/* /proc/lke-eop 파일을 등록합니다.
	 *
	 *   S_IWUGO: 모든 사용자가 쓰기 권한을 가지도록 합니다.
	 * &eop_fops: 파일을 대상으로 한 작업의 구현을 지정합니다.
	 */
	proc_eop = proc_create("lke-eop", S_IWUGO, NULL, &eop_fops);

	/* 운영체제 메모리가 부족하면 proc_create() 함수 호출이 실패합니다.
	 * ENOMEM 오류 코드를 반환하여 사용자에게 이 상태를 통보합니다.
	 */
	if (!proc_eop)
		return -ENOMEM;

	/* 모듈 부착(load)이 성공하였다는 메시지를 출력합니다. */
	pr_info("loaded\n");

	/* 작업이 성공하였음을 나타냅니다. */
	return 0;
}

/* 모듈 탈착(unload) 시 호출되는 함수입니다. */
void __exit cleanup_module(void)
{
	/* 앞서 등록한 /proc/lke-eop 파일을 시스템으로부터 등록 해제합니다. */
	proc_remove(proc_eop);

	/* 모듈 탈착(unload)이 성공하였다는 메시지를 출력합니다. */
	pr_info("unloaded\n");
}

MODULE_LICENSE("GPL");  /* 모듈 사용 허가(license)를 명시합니다. */
