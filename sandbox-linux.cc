#ifdef USE_SANDBOX

#ifdef USE_SSL_PRIVSEP
#error "Do not mix SSL PRIVSEP and SANDBOXING"
#endif

#include <linux/audit.h>
#include <linux/filter.h>
#include <sys/prctl.h>
#include <asm/unistd.h>
#include <stdint.h>
#include <stddef.h>
#include <cstring>
#include <string>
#include "config.h"

using namespace std;

/* structures and filter with help from OpenSSH 6.0 code and "fancy seccomp-bpf.h" */


#ifndef SECCOMP_MODE_FILTER
#define SECCOMP_MODE_FILTER	2 /* uses user-supplied filter. */
#define SECCOMP_RET_KILL	0x00000000U /* kill the task immediately */
#define SECCOMP_RET_TRAP	0x00030000U /* disallow and force a SIGSYS */
#define SECCOMP_RET_ALLOW	0x7fff0000U /* allow */
#define SECCOMP_RET_ERRNO	0x00050000U /* returns an errno */


struct seccomp_data {
	int nr;
	uint32_t arch;
	uint64_t instruction_pointer;
	uint64_t args[6];
};

#endif

#if defined(__i386__)
#define REG_SYSCALL REG_EAX
#define SECCOMP_AUDIT_ARCH AUDIT_ARCH_I386
#elif defined(__x86_64__)
#define REG_SYSCALL REG_RAX
#define SECCOMP_AUDIT_ARCH AUDIT_ARCH_X86_64
#else
#warning "Platform does not support seccomp filter yet"
#define REG_SYSCALL 0
#define SECCOMP_AUDIT_ARCH 0
#endif

#define SC_DENY(_nr, _errno) \
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_ ## _nr, 0, 1), \
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO|(_errno))
#define SC_ALLOW(_nr) \
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_ ## _nr, 0, 1), \
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)


#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif


static const struct sock_filter prefix[] = {
	/* validate arch */
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, arch)),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SECCOMP_AUDIT_ARCH, 1, 0),
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),

	/* load syscall nr */
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),

	SC_ALLOW(gettimeofday),
	SC_ALLOW(read),
	SC_ALLOW(write),
	SC_ALLOW(pread64),
	SC_ALLOW(ioctl),
	SC_ALLOW(accept4),
	SC_ALLOW(fcntl),
	SC_ALLOW(recvfrom),
	SC_ALLOW(brk),
	SC_ALLOW(close),
	SC_ALLOW(sendfile),
	SC_ALLOW(poll),
	SC_ALLOW(stat),
	SC_ALLOW(fstat),
	SC_ALLOW(lstat),
	SC_ALLOW(geteuid),
	SC_ALLOW(shutdown),
	SC_ALLOW(rt_sigreturn),
	SC_ALLOW(open),
	SC_ALLOW(openat),
	SC_ALLOW(getdents),
	SC_ALLOW(exit_group)
};

static const struct sock_filter suffix[] = {
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)
};


static const struct sock_filter f1[] = {
	SC_ALLOW(mmap),
	SC_ALLOW(munmap),
	SC_ALLOW(ftruncate)
};


int sandbox()
{
	int r;

	if ((r = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) < 0)
		return -1;

	struct sock_fprog filter;
	uint16_t flen = sizeof(prefix)/sizeof(prefix[0]) + 1, idx = 0;
	if (httpd_config::log_provider == string("mmap"))
		flen += sizeof(f1)/sizeof(f1[0]);

	filter.len = flen;
	filter.filter = new sock_filter[flen];

	memcpy(filter.filter, prefix, sizeof(prefix));
	idx += sizeof(prefix)/sizeof(prefix[0]);
	if (httpd_config::log_provider == string("mmap")) {
		memcpy(&filter.filter[idx], f1, sizeof(f1));
		idx += sizeof(f1)/sizeof(f1[0]);
	}

	memcpy(&filter.filter[idx], suffix, sizeof(suffix));

	r = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &filter);
	delete [] filter.filter;

	if (r < 0)
		return -1;
	return 0;
}

#else

int sandbox()
{
	return 0;
}

#endif



