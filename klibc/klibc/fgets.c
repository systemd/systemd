/*
 * fgets.c
 *
 * This will be very slow due to the implementation of getc(),
 * but we can't afford to drain characters we don't need from
 * the input.
 */

#include <stdio.h>

char *fgets(char *s, int n, FILE *f)
{
  int ch;
  char *p = s;

  while ( n > 1 ) {
    ch = getc(f);
    if ( ch == EOF ) {
      *p = '\0';
      return NULL;
    }
    *p++ = ch;
    n--;
    if ( ch == '\n' )
      break;
  }
  if ( n )
    *p = '\0';
  
  return s;
}


    
