/*
 * assert.h
 */

#ifndef _ASSERT_H
#define _ASSERT_H

#ifdef NDEBUG

#define assert(x) ((void)(x))

#else

extern void __assert_fail(const char *, const char *,
			  unsigned int);

#define assert(x) ((x) ? (void)0 : __assert_fail(#x, __FILE__, __LINE__))

#endif

#endif /* _ASSERT_H */

