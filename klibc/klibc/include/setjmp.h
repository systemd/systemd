/*
 * setjmp.h
 */

#ifndef _SETJMP_H
#define _SETJMP_H

#include <klibc/extern.h>
#include <klibc/compiler.h>
#include <stddef.h>
#include <signal.h>

#include <klibc/archsetjmp.h>

__extern int setjmp(jmp_buf);
__extern __noreturn longjmp(jmp_buf, int);

/*
  Whose bright idea was it to add unrelated functionality to just about
  the only function in the standard C library (setjmp) which cannot be
  wrapped by an ordinary function wrapper?  Anyway, the damage is done,
  and therefore, this wrapper *must* be inline.  However, gcc will
  complain if this is an inline function for unknown reason, and
  therefore sigsetjmp() needs to be a macro.
*/

struct __sigjmp_buf {
  jmp_buf __jmpbuf;
  sigset_t __sigs;
};

typedef struct __sigjmp_buf sigjmp_buf[1];

#define sigsetjmp(__env, __save) \
({ \
  struct __sigjmp_buf *__e = (__env); \
  sigprocmask(0, NULL, &__e->__sigs); \
  setjmp(__e->__jmpbuf); \
})

__extern __noreturn siglongjmp(sigjmp_buf, int);

#endif /* _SETJMP_H */
