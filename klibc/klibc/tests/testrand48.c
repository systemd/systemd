#include <stdlib.h>
#include <stdio.h>

int main(void)
{
  unsigned short seed1[] = { 0x1234, 0x5678, 0x9abc };
  unsigned short *oldseed;

  oldseed = seed48(seed1);
  printf("Initial seed: %#06x %#06x %#06x\n",
	 oldseed[0], oldseed[1], oldseed[2]);

  printf("lrand48() = %ld\n", lrand48());

  seed48(seed1);
  printf("mrand48() = %ld\n", mrand48());

  return 1;
}
