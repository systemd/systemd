/*
 * siglongjmp.c
 *
 * sigsetjmp() is a macro, by necessity (it's either that or write
 * it in assembly), but siglongjmp() is a normal function.
 */

#include <setjmp.h>
#include <signal.h>

__noreturn siglongjmp(sigjmp_buf buf, int retval)
{
  sigprocmask(SIG_SETMASK, &buf->__sigs, NULL);
  longjmp(buf->__jmpbuf, retval);
}

