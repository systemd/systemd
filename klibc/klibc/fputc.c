/*
 * fputc.c
 *
 * gcc "printf decompilation" expects this to exist...
 */

#include <stdio.h>

int fputc(int c, FILE *f)
{
  unsigned char ch = c;

  return _fwrite(&ch, 1, f) == 1 ? ch : EOF;
}
