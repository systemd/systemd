#include <stdint.h>
#include <asm/gentrap.h>
#include <asm/pal.h>

#if BITS == 64
typedef uint64_t uint;
typedef int64_t  sint;
#else
typedef uint32_t uint;
typedef int32_t  sint;
#endif

#ifdef SIGNED
typedef sint xint;
#else
typedef uint xint;
#endif

xint NAME (uint num, uint den)
{
  uint quot = 0, qbit = 1;
  int minus = 0;
  xint v;
  
  if ( den == 0 ) {
    /* This is really $16, but $16 and $24 are exchanged by a script */
    register unsigned long cause asm("$24") = GEN_INTDIV;
    asm volatile("call_pal %0" :: "i" (PAL_gentrap), "r" (cause));
    return 0;			/* If trap returns... */
  }

#if SIGNED
  if ( (sint)(num^den) < 0 )
    minus = 1;
  if ( (sint)num < 0 ) num = -num;
  if ( (sint)den < 0 ) den = -den;
#endif

  /* Left-justify denominator and count shift */
  while ( (sint)den >= 0 ) {
    den <<= 1;
    qbit <<= 1;
  }

  while ( qbit ) {
    if ( den <= num ) {
      num -= den;
      quot += qbit;
    }
    den >>= 1;
    qbit >>= 1;
  }

  v = (xint)(REM ? num : quot);
  if ( minus ) v = -v;
  return v;
}
