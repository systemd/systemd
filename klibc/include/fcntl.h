/*
 * fcntl.h
 */

#ifndef _FCNTL_H
#define _FCNTL_H

#include <klibc/extern.h>
#include <klibc/compiler.h>
#include <sys/types.h>
#if defined(__mips__) && !defined(__mips64__)
# include <klibc/archfcntl.h>
#endif
#include <linux/fcntl.h>

/* This is ugly, but "struct flock" has actually been defined with
   a long off_t, so it's really "struct flock64".  It just happens
   to work.  Gag.  Barf.

   This happens to work on all 32-bit architectures except MIPS. */

#ifdef F_GETLK64
# undef F_GETLK
# define F_GETLK F_GETLK64
#endif

#ifdef F_SETLK64
# undef F_SETLK
# define F_SETLK F_SETLK64
#endif

#ifdef F_SETLKW64
# undef F_SETLKW
# define F_SETLKW F_SETLKW64
#endif

/* This is defined here as well as in <unistd.h> since old-style code
   would still include <fcntl.h> when using open(), and open() being
   a varadic function changes its calling convention on some architectures. */
#ifndef _KLIBC_IN_OPEN_C
__extern int open(const char *, int, ...);
#endif

__extern int fcntl(int, int, ...);

#endif /* _FCNTL_H */
