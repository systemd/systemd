/*
 * inttypes.h
 */

#ifndef _INTTYPES_H
#define _INTTYPES_H

#include <klibc/extern.h>
#include <stdint.h>
#include <stddef.h>

static __inline__ intmax_t imaxabs(intmax_t __n)
{
  return (__n < (intmax_t)0) ? -__n : __n;
}

__extern intmax_t strtoimax(const char *, char **, int);
__extern uintmax_t strtoumax(const char *, char **, int);

/* extensions */
__extern intmax_t strntoimax(const char *, char **, int, size_t);
__extern uintmax_t strntoumax(const char *, char **, int, size_t);

#if !defined(__cplusplus) || defined(__STDC_FORMAT_MACROS)

#define PRId8	"d"
#define PRId16	"d"
#define PRId32	"d"
#define PRId64	__PRI64_RANK "d"

#define PRIdLEAST8	"d"
#define PRIdLEAST16	"d"
#define PRIdLEAST32	"d"
#define PRIdLEAST64	__PRI64_RANK "d"

#define PRIdFAST8	"d"
#define PRIdFAST16	__PRIFAST_RANK "d"
#define PRIdFAST32	__PRIFAST_RANK "d"
#define PRIdFAST64	__PRI64_RANK "d"

#define PRIdMAX	 __PRI64_RANK "d"
#define PRIdPTR  __PRIPTR_RANK "d"

#define PRIi8	"i"
#define PRIi16	"i"
#define PRIi32	"i"
#define PRIi64	__PRI64_RANK "i"

#define PRIiLEAST8	"i"
#define PRIiLEAST16	"i"
#define PRIiLEAST32	"i"
#define PRIiLEAST64	__PRI64_RANK "i"

#define PRIiFAST8	"i"
#define PRIiFAST16	__PRIFAST_RANK "i"
#define PRIiFAST32	__PRIFAST_RANK "i"
#define PRIiFAST64	__PRI64_RANK "i"

#define PRIiMAX	 __PRI64_RANK "i"
#define PRIiPTR  __PRIPTR_RANK "i"

#define PRIo8	"o"
#define PRIo16	"o"
#define PRIo32	"o"
#define PRIo64	__PRI64_RANK "o"

#define PRIoLEAST8	"o"
#define PRIoLEAST16	"o"
#define PRIoLEAST32	"o"
#define PRIoLEAST64	__PRI64_RANK "o"

#define PRIoFAST8	"o"
#define PRIoFAST16	__PRIFAST_RANK "o"
#define PRIoFAST32	__PRIFAST_RANK "o"
#define PRIoFAST64	__PRI64_RANK "o"

#define PRIoMAX	 __PRI64_RANK "o"
#define PRIoPTR  __PRIPTR_RANK "o"

#define PRIu8	"u"
#define PRIu16	"u"
#define PRIu32	"u"
#define PRIu64	__PRI64_RANK "u"

#define PRIuLEAST8	"u"
#define PRIuLEAST16	"u"
#define PRIuLEAST32	"u"
#define PRIuLEAST64	__PRI64_RANK "u"

#define PRIuFAST8	"u"
#define PRIuFAST16	__PRIFAST_RANK "u"
#define PRIuFAST32	__PRIFAST_RANK "u"
#define PRIuFAST64	__PRI64_RANK "u"

#define PRIuMAX	 __PRI64_RANK "u"
#define PRIuPTR  __PRIPTR_RANK "u"

#define PRIx8	"x"
#define PRIx16	"x"
#define PRIx32	"x"
#define PRIx64	__PRI64_RANK "x"

#define PRIxLEAST8	"x"
#define PRIxLEAST16	"x"
#define PRIxLEAST32	"x"
#define PRIxLEAST64	__PRI64_RANK "x"

#define PRIxFAST8	"x"
#define PRIxFAST16	__PRIFAST_RANK "x"
#define PRIxFAST32	__PRIFAST_RANK "x"
#define PRIxFAST64	__PRI64_RANK "x"

#define PRIxMAX	 __PRI64_RANK "x"
#define PRIxPTR  __PRIPTR_RANK "x"

#define PRIX8	"X"
#define PRIX16	"X"
#define PRIX32	"X"
#define PRIX64	__PRI64_RANK "X"

#define PRIXLEAST8	"X"
#define PRIXLEAST16	"X"
#define PRIXLEAST32	"X"
#define PRIXLEAST64	__PRI64_RANK "X"

#define PRIXFAST8	"X"
#define PRIXFAST16	__PRIFAST_RANK "X"
#define PRIXFAST32	__PRIFAST_RANK "X"
#define PRIXFAST64	__PRI64_RANK "X"

#define PRIXMAX	 __PRI64_RANK "X"
#define PRIXPTR  __PRIPTR_RANK "X"

#define SCNd8	"hhd"
#define SCNd16	"hd"
#define SCNd32	"d"
#define SCNd64	__PRI64_RANK "d"

#define SCNdLEAST8	"hhd"
#define SCNdLEAST16	"hd"
#define SCNdLEAST32	"d"
#define SCNdLEAST64	__PRI64_RANK "d"

#define SCNdFAST8	"hhd"
#define SCNdFAST16	__PRIFAST_RANK "d"
#define SCNdFAST32	__PRIFAST_RANK "d"
#define SCNdFAST64	__PRI64_RANK "d"

#define SCNdMAX	 __PRI64_RANK "d"
#define SCNdPTR  __PRIPTR_RANK "d"

#define SCNi8	"hhi"
#define SCNi16	"hi"
#define SCNi32	"i"
#define SCNi64	__PRI64_RANK "i"

#define SCNiLEAST8	"hhi"
#define SCNiLEAST16	"hi"
#define SCNiLEAST32	"i"
#define SCNiLEAST64	__PRI64_RANK "i"

#define SCNiFAST8	"hhi"
#define SCNiFAST16	__PRIFAST_RANK "i"
#define SCNiFAST32	__PRIFAST_RANK "i"
#define SCNiFAST64	__PRI64_RANK "i"

#define SCNiMAX	 __PRI64_RANK "i"
#define SCNiPTR  __PRIPTR_RANK "i"

#define SCNo8	"hho"
#define SCNo16	"ho"
#define SCNo32	"o"
#define SCNo64	__PRI64_RANK "o"

#define SCNoLEAST8	"hho"
#define SCNoLEAST16	"ho"
#define SCNoLEAST32	"o"
#define SCNoLEAST64	__PRI64_RANK "o"

#define SCNoFAST8	"hho"
#define SCNoFAST16	__PRIFAST_RANK "o"
#define SCNoFAST32	__PRIFAST_RANK "o"
#define SCNoFAST64	__PRI64_RANK "o"

#define SCNoMAX	 __PRI64_RANK "o"
#define SCNoPTR  __PRIPTR_RANK "o"

#define SCNu8	"hhu"
#define SCNu16	"hu"
#define SCNu32	"u"
#define SCNu64	__PRI64_RANK "u"

#define SCNuLEAST8	"hhu"
#define SCNuLEAST16	"hu"
#define SCNuLEAST32	"u"
#define SCNuLEAST64	__PRI64_RANK "u"

#define SCNuFAST8	"hhu"
#define SCNuFAST16	__PRIFAST_RANK "u"
#define SCNuFAST32	__PRIFAST_RANK "u"
#define SCNuFAST64	__PRI64_RANK "u"

#define SCNuMAX	 __PRI64_RANK "u"
#define SCNuPTR  __PRIPTR_RANK "u"

#define SCNx8	"hhx"
#define SCNx16	"hx"
#define SCNx32	"x"
#define SCNx64	__PRI64_RANK "x"

#define SCNxLEAST8	"hhx"
#define SCNxLEAST16	"hx"
#define SCNxLEAST32	"x"
#define SCNxLEAST64	__PRI64_RANK "x"

#define SCNxFAST8	"hhx"
#define SCNxFAST16	__PRIFAST_RANK "x"
#define SCNxFAST32	__PRIFAST_RANK "x"
#define SCNxFAST64	__PRI64_RANK "x"

#define SCNxMAX	 __PRI64_RANK "x"
#define SCNxPTR  __PRIPTR_RANK "x"

#endif

#endif /* _INTTYPES_H */
