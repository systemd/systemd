/*
 * srand48.c
 */

#include <stdlib.h>
#include <stdint.h>

unsigned short __rand48_seed[3]; /* Common with mrand48.c, lrand48.c */

void srand48(long seedval)
{
  __rand48_seed[0] = 0x330e;
  __rand48_seed[1] = (unsigned short)seedval;
  __rand48_seed[2] = (unsigned short)((uint32_t)seedval >> 16);
}
