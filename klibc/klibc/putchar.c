/*
 * putchar.c
 *
 * - gcc wants this
 */

#include <stdio.h>

#undef putchar			/* Defined as a macro */
int putchar(int);

int putchar(int c)
{
  return fputc(c, stdout);
}
