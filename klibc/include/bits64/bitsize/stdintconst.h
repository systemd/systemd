/*
 * bits64/stdintconst.h
 */

#ifndef _BITSIZE_STDINTCONST_H
#define _BITSIZE_STDINTCONST_H

#define INT_FAST16_C(c)	 INT64_C(c)
#define INT_FAST32_C(c)  INT64_C(c)

#define UINT_FAST16_C(c) UINT64_C(c)
#define UINT_FAST32_C(c) UINT64_C(c)

#define INTPTR_C(c)	 INT64_C(c)
#define UINTPTR_C(c)	 UINT64_C(c)
#define PTRDIFF_C(c)     INT64_C(c)

#endif /* _BITSIZE_STDINTCONST_H */
