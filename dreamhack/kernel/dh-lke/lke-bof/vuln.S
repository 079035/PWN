	.intel_syntax noprefix
	.text

	# void bof_func(const char __user *buf, size_t count)
	.globl bof_func
	.type bof_func, @function
bof_func:
	# {
			.cfi_startproc
	push rbp
			.cfi_def_cfa_offset 16
			.cfi_offset 6, -16
	mov rbp, rsp
			.cfi_def_cfa_register 6
	sub rsp, 0x70

	lea rax, .Lleave_ret[rip]
	lea rcx, [rsi - 1]
	and rcx, ~7
	mov [rsp + rcx], rax    # *(RSP + ((count - 1) & ~0x7)) = &.Lleave_ret;

	mov rdx, rsi
	mov rsi, rdi
	lea rdi, [rsp - 0x8]
	xor eax, eax
	call _copy_from_user    # copy_from_user(RSP - 8, buf, count);

	# }
.Lleave_ret:
	leave
			.cfi_restore 6
			.cfi_def_cfa 7, 8
	ret
			.cfi_endproc
	.size bof_func, .-bof_func

	.section .note.GNU-stack, "", @progbits
