/*
 * qsort.c
 *
 * This is actually combsort.  It's an O(n log n) algorithm with
 * simplicity/small code size being its main virtue.
 */

#include <stddef.h>
#include <string.h>

static inline size_t newgap(size_t gap)
{
  gap = (gap*10)/13;
  if ( gap == 9 || gap == 10 )
    gap = 11;

  if ( gap < 1 )
    gap = 1;
  return gap;
}

void qsort(void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *))
{
  size_t gap = nmemb;
  size_t i, j;
  void *p1, *p2;
  int swapped;

  do {
    gap = newgap(gap);
    swapped = 0;
    
    for ( i = 0, p1 = base ; i < nmemb-gap ; i++, (char *)p1 += size ) {
      j = i+gap;
      if ( compar(p1, p2 = (char *)base+j*size) > 0 ) {
	memswap(p1, p2, size);
	swapped = 1;
      }
    }
  } while ( gap > 1 || swapped );
}

