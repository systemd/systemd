#include <stdint.h>
#include <signal.h>

#if BITS == 64
typedef uint64_t unum;
typedef int64_t  snum;
#else
typedef uint32_t unum;
typedef int32_t  snum;
#endif

#ifdef SIGNED
typedef snum xnum;
#else
typedef unum xnum;
#endif

#ifdef __cris__
static inline unum __attribute__((const)) dstep(unum rs, unum rd) {
  asm("dstep %1,%0" : "+r" (rd) : "r" (rs));
  return rd;
}

static inline unum __attribute__((const)) lz(unum rs) {
  unum rd;
  asm("lz %1,%0" : "=r" (rd) : "r" (rs));
  return rd;
}

#else
/* For testing */
static inline unum __attribute__ ((const)) dstep(unum rs, unum rd) {
  rd <<= 1;
  if ( rd >= rs )
    rd -= rs;

  return rd;
}

static inline unum __attribute__((const)) lz(unum rs) {
  unum rd = 0;
  while ( rs >= 0x7fffffff ) {
    rd++;
    rs <<= 1;
  }
  return rd;
}

#endif

xnum NAME (unum num, unum den)
{
  unum quot = 0, qbit = 1;
  int minus = 0;
  xnum v;
  
  if ( den == 0 ) {
    raise(SIGFPE);
    return 0;			/* If signal ignored... */
  }

  if (den == 1) return (xnum)(REM ? 0 : num);

#if SIGNED
  if ( (snum)(num^den) < 0 )
    minus = 1;
  if ( (snum)num < 0 ) num = -num;
  if ( (snum)den < 0 ) den = -den;
#endif

  den--;


  /* Left-justify denominator and count shift */
  while ( (snum)den >= 0 ) {
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

  v = (xnum)(REM ? num : quot);
  if ( minus ) v = -v;
  return v;
}
