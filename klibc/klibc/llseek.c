/*
 * llseek.c
 *
 * On 32-bit platforms, we need llseek() as well as lseek() to be
 * able to handle large disks
 */

#include <unistd.h>
#include <sys/syscall.h>

#if BITSIZE == 32

static inline _syscall5(int, _llseek, int, fd, unsigned long, hi, unsigned long, lo, loff_t *,res, int, whence);

loff_t llseek(int fd, loff_t offset, int whence)
{
  loff_t result;
  int rv;

  rv = _llseek(fd, (unsigned long)(offset >> 32),
		(unsigned long)offset, &result, whence);
  
  return rv ? (loff_t)-1 : result;
}

#else

loff_t llseek(int fd, loff_t offset, int whence)
{
  return lseek(fd, offset, whence);
}

#endif

