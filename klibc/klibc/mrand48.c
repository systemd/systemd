/*
 * mrand48.c
 */

#include <stdlib.h>
#include <stdint.h>

unsigned short __rand48_seed[3]; /* Common with lrand48.c, srand48.c */

long mrand48(void)
{
  return jrand48(__rand48_seed);
}
