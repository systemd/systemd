#include <unistd.h>
#include <sys/syscall.h>

/* pipe() on alpha returns both file descriptors in registers --
   $0 and $20 respectively.  This is unlike any other system call,
   as far as I can tell. */

int pipe(int *fds)
{
  register long sc_0 __asm__("$0");
  register long sc_19 __asm__("$19");
  register long sc_20 __asm__("$20");

  sc_0 = __NR_pipe;
  asm volatile("callsys" : "=r" (sc_0), "=r" (sc_19), "=r" (sc_20)
	       : "0" (sc_0)
	       : _syscall_clobbers);
  
  if ( sc_19 ) {
    errno = sc_19;
    return -1;
  }

  fds[0] = sc_0;
  fds[1] = sc_20;

  return 0;
}
