/*
 * lrand48.c
 */

#include <stdlib.h>
#include <stdint.h>

unsigned short __rand48_seed[3]; /* Common with mrand48.c, srand48.c */

long lrand48(void)
{
  return (uint32_t)jrand48(__rand48_seed) >> 1;
}

