/*
 * mmap.c
 */

#include <stdint.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <unistd.h>
#include <asm/page.h>		/* For PAGE_SHIFT */

#if defined(__sparc__)
# define MMAP2_SHIFT	12	/* Fixed by syscall definition */
#elif defined(__mips__) || defined(__powerpc__)
# define MMAP2_SHIFT	__getpageshift() /* Variable */
#else
# define MMAP2_SHIFT	PAGE_SHIFT
#endif

/*
 * Set in SYSCALLS whether or not we should use an unadorned mmap() system
 * call (typical on 64-bit architectures).
 */
#if (BITSIZE == 32 && defined(__NR_mmap2)) || (BITSIZE == 64 && !defined(__NR_mmap))

/* This architecture uses mmap2(). The Linux mmap2() system call takes
   a page offset as the offset argument.  We need to make sure we have
   the proper conversion in place. */

extern void *__mmap2(void *, size_t, int, int, int, size_t);

void *mmap(void *start, size_t length, int prot, int flags, int fd, off_t offset)
{
  const int mmap2_shift = MMAP2_SHIFT;
  const unsigned long mmap2_mask = (1UL << mmap2_shift) - 1;

  if ( offset & mmap2_mask ) {
    errno = EINVAL;
    return MAP_FAILED;
  }

  return __mmap2(start, length, prot, flags, fd, (size_t)offset >> mmap2_shift);
}

#endif


    
  
