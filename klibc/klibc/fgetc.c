/*
 * fgetc.c
 *
 * Extremely slow fgetc implementation, using _fread().  If people
 * actually need character-oriented input to be fast, we may actually
 * have to implement buffering.  Sigh.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

int fgetc(FILE *f)
{
  unsigned char ch;

  return (_fread(&ch, 1, f) == 1) ? (int)ch : EOF;
}

