/*
 * stdint.h
 */

#ifndef _STDINT_H
#define _STDINT_H

#include <bitsize/stdint.h>

typedef int8_t   int_least8_t;
typedef int16_t  int_least16_t;
typedef int32_t  int_least32_t;
typedef int64_t  int_least64_t;

typedef uint8_t  uint_least8_t;
typedef uint16_t uint_least16_t;
typedef uint32_t uint_least32_t;
typedef uint64_t uint_least64_t;

typedef int8_t   int_fast8_t;
typedef int64_t  int_fast64_t;

typedef uint8_t  uint_fast8_t;
typedef uint64_t uint_fast64_t;

typedef int64_t  intmax_t;
typedef uint64_t uintmax_t;

#if !defined(__cplusplus) || defined(__STDC_LIMIT_MACROS)

#define INT8_MIN	(-128)
#define INT16_MIN	(-32768)
#define INT32_MIN	(-2147483647-1)
#define INT64_MIN	(__INT64_C(-9223372036854775807)-1)

#define INT8_MAX	(127)
#define INT16_MAX	(32767)
#define INT32_MAX	(2147483647)
#define INT64_MAX	(__INT64_C(9223372036854775807))

#define UINT8_MAX	(255U)
#define UINT16_MAX	(65535U)
#define UINT32_MAX	(4294967295U)
#define UINT64_MAX	(__UINT64_C(18446744073709551615))

#define INT_LEAST8_MIN	INT8_MIN
#define INT_LEAST16_MIN	INT16_MIN
#define INT_LEAST32_MIN	INT32_MIN
#define INT_LEAST64_MIN	INT64_MIN

#define INT_LEAST8_MAX	INT8_MAX
#define INT_LEAST16_MAX	INT16_MAX
#define INT_LEAST32_MAX	INT32_MAX
#define INT_LEAST64_MAX	INT64_MAX

#define UINT_LEAST8_MAX	 UINT8_MAX
#define UINT_LEAST16_MAX UINT16_MAX
#define UINT_LEAST32_MAX UINT32_MAX
#define UINT_LEAST64_MAX UINT64_MAX

#define INT_FAST8_MIN	INT8_MIN
#define INT_FAST64_MIN	INT64_MIN

#define INT_FAST8_MAX	INT8_MAX
#define INT_FAST64_MAX	INT64_MAX

#define UINT_FAST8_MAX	UINT8_MAX
#define UINT_FAST64_MAX UINT64_MAX

#define INTMAX_MIN	INT64_MIN
#define INTMAX_MAX	INT64_MAX
#define UINTMAX_MAX	UINT64_MAX

#include <bitsize/stdintlimits.h>

#endif

#if !defined(__cplusplus) || defined(__STDC_CONSTANT_MACROS)

#define INT8_C(c)	c
#define INT16_C(c)	c
#define INT32_C(c)	c
#define INT64_C(c)	__INT64_C(c)

#define UINT8_C(c)	c ## U
#define UINT16_C(c)	c ## U
#define UINT32_C(c)	c ## U
#define UINT64_C(c)	__UINT64_C(c)

#define INT_LEAST8_C(c)	 INT8_C(c)
#define INT_LEAST16_C(c) INT16_C(c)
#define INT_LEAST32_C(c) INT32_C(c)
#define INT_LEAST64_C(c) INT64_C(c)

#define UINT_LEAST8_C(c)  UINT8_C(c)
#define UINT_LEAST16_C(c) UINT16_C(c)
#define UINT_LEAST32_C(c) UINT32_C(c)
#define UINT_LEAST64_C(c) UINT64_C(c)

#define INT_FAST8_C(c)	INT8_C(c)
#define INT_FAST64_C(c) INT64_C(c)

#define UINT_FAST8_C(c)  UINT8_C(c)
#define UINT_FAST64_C(c) UINT64_C(c)

#define INTMAX_C(c)	INT64_C(c)
#define UINTMAX_C(c)	UINT64_C(c)

#include <bitsize/stdintconst.h>

#endif

#endif /* _STDINT_H */
