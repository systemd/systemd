/*
 * strspn, strcspn
 */

#include <string.h>
#include <stddef.h>
#include <inttypes.h>
#include <limits.h>

#ifndef LONG_BIT
#define LONG_BIT (CHAR_BIT*sizeof(long))
#endif

static inline void
set_bit(unsigned long *bitmap, unsigned int bit)
{
  bitmap[bit/LONG_BIT] |= 1UL << (bit%LONG_BIT);
}

static inline int
test_bit(unsigned long *bitmap, unsigned int bit)
{
  return (int)(bitmap[bit/LONG_BIT] >> (bit%LONG_BIT)) & 1;
}

static size_t
strxspn(const char *s, const char *map, int parity)
{
  unsigned long matchmap[((1 << CHAR_BIT)+LONG_BIT-1)/LONG_BIT];
  size_t n = 0;

  /* Create bitmap */
  memset(matchmap, 0, sizeof matchmap);
  while ( *map )
    set_bit(matchmap, (unsigned char) *map++);

  /* Make sure the null character never matches */
  if ( parity )
    set_bit(matchmap, 0);

  /* Calculate span length */
  while ( test_bit(matchmap, (unsigned char) *s++)^parity )
    n++;

  return n;
}

size_t
strspn(const char *s, const char *accept)
{
  return strxspn(s, accept, 0);
}

size_t
strcspn(const char *s, const char *reject)
{
  return strxspn(s, reject, 1);
}

char *
strpbrk(const char *s, const char *accept)
{
  const char *ss = s+strxspn(s, accept, 1);
  
  return *ss ? (char *)ss : NULL;
}

