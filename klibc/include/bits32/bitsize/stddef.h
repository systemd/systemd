/*
 * bits32/stddef.h
 */

#ifndef _BITSIZE_STDDEF_H
#define _BITSIZE_STDDEF_H

#define _SIZE_T
#if defined(__s390__) || defined(__hppa__) || defined(__cris__)
typedef unsigned long size_t;
#else
typedef unsigned int size_t;
#endif

#define _PTRDIFF_T
typedef signed int   ptrdiff_t;

#endif /* _BITSIZE_STDDEF_H */
