/*
 * mmap.c
 */

#include <stdint.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <asm/page.h>		/* For PAGE_SHIFT */

#if defined(__sparc__)
# define MMAP2_SHIFT	12	/* Fixed by syscall definition */
#else
# define MMAP2_SHIFT	PAGE_SHIFT
#endif
#define MMAP2_MASK	((1UL << MMAP2_SHIFT)-1)

/*
 * Prefer mmap2() over mmap(), except on the architectures listed
 */

#if defined(__NR_mmap2) && !defined(__sparc__) && !defined(__ia64__) && !defined(__powerpc__) && !defined(__powerpc64__)

/* This architecture uses mmap2() */

static inline _syscall6(void *,mmap2,void *,start,size_t,length,int,prot,int,flags,int,fd,off_t,offset);

/* The Linux mmap2() system call takes a page offset as the offset argument.
   We need to make sure we have the proper conversion in place. */

void *mmap(void *start, size_t length, int prot, int flags, int fd, off_t offset)
{
  if ( offset & MMAP2_MASK ) {
    errno = EINVAL;
    return MAP_FAILED;
  }

  return mmap2(start, length, prot, flags, fd, (size_t)offset >> MMAP2_SHIFT);
}

#else

/* This architecture uses a plain mmap() system call */
/* Only use this for architectures where mmap() is a real 6-argument system call! */

_syscall6(void *,mmap,void *,start,size_t,length,int,prot,int,flags,int,fd,off_t,offset)

#endif

    
  
