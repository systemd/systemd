/*
 * klibc/compiler.h
 *
 * Various compiler features
 */

#ifndef _KLIBC_COMPILER_H
#define _KLIBC_COMPILER_H

/* Specific calling conventions */
#ifdef __i386__
# ifdef __GNUC__
#  define __cdecl __attribute__((cdecl,regparm(0)))
# else
  /* Most other C compilers have __cdecl as a keyword */
# endif
#endif

/* How to declare a function that *must* be inlined */
#ifdef __GNUC__
# if __GNUC_MAJOR__ >= 3
#  define __must_inline static __inline__ __attribute__((always_inline))
# else
#  define __must_inline extern __inline__
# endif
#else
# define __must_inline inline	/* Just hope this works... */
#endif

/* How to declare a function that does not return */
#ifdef __GNUC__
# define __noreturn void __attribute__((noreturn))
#else
# define __noreturn void
#endif

/* How to declare a "constant" function (a function in the
   mathematical sense) */
#ifdef __GNUC__
# define __constfunc __attribute__((const))
#else
# define __constfunc
#endif

/* Format attribute */
#ifdef __GNUC__
# define __formatfunc(t,f,a) __attribute__((format(t,f,a)))
#else
# define __formatfunc(t,f,a)
#endif

/* likely/unlikely */
#if defined(__GNUC__) && (__GNUC_MAJOR__ > 2 || (__GNUC_MAJOR__ == 2 && __GNUC_MINOR__ >= 95))
# define __likely(x)   __builtin_expect((x), 1)
# define __unlikely(x) __builtin_expect((x), 0)
#else
# define __likely(x)   (x)
# define __unlikely(x) (x)
#endif

#endif
