/*
 * strtoimaxtest.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

int main(int argc, char *argv[])
{
  int i;
  char *ep;
  intmax_t iv;

  for ( i = 1 ; i < argc ; i++ ) {
    iv = strtoimax(argv[i], &ep, 0);
    printf("strtoimax(\"%s\") = %jd\n", argv[i], iv);
    if ( *ep )
      printf("   ep = \"%s\"\n", ep);
  }

  return 0;
}

