#include <unistd.h>
#include <stdio.h>

int main(void)
{
  printf("getpagesize()    = %d\n"
	 "__getpageshift() = %d\n",
	 getpagesize(), __getpageshift());

  return 0;
}
