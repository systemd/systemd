/*
 * strpbrk
 */

#include <string.h>
#include <stddef.h>
#include <inttypes.h>
#include <limits.h>
#include "strxspn.h"

size_t
__strxspn(const char *s, const char *map, int parity)
{
  char matchmap[UCHAR_MAX+1];
  size_t n = 0;

  /* Create bitmap */
  memset(matchmap, 0, sizeof matchmap);
  while ( *map )
    matchmap[(unsigned char) *map++] = 1;
  
  /* Make sure the null character never matches */
  matchmap[0] = parity;

  /* Calculate span length */
  while ( matchmap[(unsigned char) *s++] ^ parity )
    n++;

  return n;
}
