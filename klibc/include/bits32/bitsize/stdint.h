/*
 * bits32/stdint.h
 */

#ifndef _BITSIZE_STDINT_H
#define _BITSIZE_STDINT_H

typedef signed char 		int8_t;
typedef short int		int16_t;
typedef int			int32_t;
typedef long long int		int64_t;

typedef unsigned char 		uint8_t;
typedef unsigned short int	uint16_t;
typedef unsigned int		uint32_t;
typedef unsigned long long int	uint64_t;

typedef int			int_fast16_t;
typedef int			int_fast32_t;

typedef unsigned int		uint_fast16_t;
typedef unsigned int		uint_fast32_t;

typedef int			intptr_t;
typedef unsigned int		uintptr_t;

#define __INT64_C(c)   c ## LL
#define __UINT64_C(c)  c ## ULL

#define __PRI64_RANK   "ll"
#define __PRIFAST_RANK ""
#define __PRIPTR_RANK  ""

#endif /* _BITSIZE_STDINT_H */
