#include <sys/types.h>
#include <linux/unistd.h>

struct mmap_arg_struct {
	unsigned long addr;
	unsigned long len;
	unsigned long prot;
	unsigned long flags;
	unsigned long fd;
	unsigned long offset;
};

void * __mmap2(void * addr, size_t len, int prot, int flags,
						 int fd, long offset)
{
	struct mmap_arg_struct args = {
		(unsigned long) addr,
		(unsigned long) len,
		(unsigned long) prot,
		(unsigned long) flags,
		(unsigned long) fd,
		(unsigned long) offset,
	};

	register struct mmap_arg_struct *__arg1 asm("2") = &args;
	register long __svcres asm("2");
	unsigned long __res;

	__asm__ __volatile__ (
		"    svc %b1\n"
		: "=d" (__svcres)
		: "i" (__NR_mmap2),
		  "0" (__arg1)
		: "1", "cc", "memory");
	__res = __svcres;
	if (__res >= (unsigned long)-125) {
		errno = -__res;
		__res = -1;
	}
	return (void *)__res;
}
