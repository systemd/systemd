/*
 * stdlib.h
 */

#ifndef _STDLIB_H
#define _STDLIB_H

#include <klibc/extern.h>
#include <klibc/compiler.h>
#include <stddef.h>

#define EXIT_FAILURE 1
#define EXIT_SUCCESS 0

static __inline__ __noreturn _Exit(int __n) {
  __extern __noreturn _exit(int);
  _exit(__n);
  for(;;);			/* Some gcc versions are stupid */
}
__extern __noreturn abort(void);
static __inline__ int abs(int __n) {
  return (__n < 0) ? -__n : __n;
}
__extern int atexit(void (*)(void));
__extern int on_exit(void (*)(int, void *), void *);
__extern int atoi(const char *);
__extern long atol(const char *);
__extern long long atoll(const char *);
__extern __noreturn exit(int);
__extern void free(void *);
static __inline__ long labs(long __n) {
  return (__n < 0L) ? -__n : __n;
}

static __inline__ long long llabs(long long __n) {
  return (__n < 0LL) ? -__n : __n;
}

__extern __mallocfunc void *malloc(size_t);
__extern __mallocfunc void *calloc(size_t, size_t);
__extern __mallocfunc void *realloc(void *, size_t);
__extern long strtol(const char *, char **, int);
__extern long long strtoll(const char *, char **, int);
__extern unsigned long strtoul(const char *, char **, int);
__extern unsigned long long strtoull(const char *, char **, int);

__extern char *getenv(const char *);
__extern int putenv(const char *);
__extern int setenv(const char *, const char *, int);
__extern int unsetenv(const char *);

__extern void qsort(void *, size_t, size_t, int (*)(const void *, const void *));


__extern long jrand48(unsigned short *);
__extern long mrand48(void);
__extern long nrand48(unsigned short *);
__extern long lrand48(void);
__extern unsigned short *seed48(const unsigned short *);
__extern void srand48(long);

#define RAND_MAX 0x7fffffff
static __inline__ int rand(void) {
  return (int)lrand48();
}
static __inline__ void srand(unsigned int __s) {
  srand48(__s);
}
static __inline__ long random(void)
{
  return lrand48();
}
static __inline__ void srandom(unsigned int __s)
{
  srand48(__s);
}

/* Basic PTY functions.  These only work if devpts is mounted! */

__extern int unlockpt(int);
__extern char *ptsname(int);
__extern int getpt(void);

static __inline__ int grantpt(int __fd)
{
  (void)__fd;
  return 0;			/* devpts does this all for us! */
}

#endif /* _STDLIB_H */
