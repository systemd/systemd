#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define NCYCLES 32768
#define NSLOTS  4096

struct slot {
  char *ptr;
  size_t size;
};

struct slot s[NSLOTS];

int main(void)
{
  size_t sp, sq;
  char *p, *ep, *q, *eq;
  int r, i, j;
  int ok;
  int err = 0;

  for ( r = 0 ; r < NCYCLES ; r++ ) {
    i = lrand48() % NSLOTS;

    if ( s[i].ptr ) {
      free(s[i].ptr);
      printf("Freed     %8zu bytes at %p\n", s[i].size, s[i].ptr);
      s[i].ptr  = NULL;
      s[i].size = 0;
    } else {
      sp = lrand48();		/* 32-bit random number */
      sp >>= 12+(lrand48() % 20);

      s[i].size = sp;
      s[i].ptr  = p = malloc(sp);
      ep = p+sp;
      ok = 1;
      for ( j = 0 ; j < NSLOTS ; j++ ) {
	q = s[j].ptr;
	if ( i != j && q ) {
	  sq = s[j].size;
	  eq = q+sq;
	  
	  if ( (p < q && ep > q) || (p >= q && p < eq) ) {
	    ok = 0;
	    err = 1;
	    break;
	  }
	}
      }
      printf("Allocated %8zu bytes at %p, ok = %d\n", sp, p, ok);

      if ( p )
	memset(p, 0xee, sp);	/* Poison this memory */
    }
  }
  return err;
}

