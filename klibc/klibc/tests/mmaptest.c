/*
 * mmaptest.c
 *
 * Test some simple cases of mmap()
 */

#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <sys/syscall.h>

int main(int argc, char *argv[])
{
  void *foo;

  (void)argc; (void)argv;

  /* Important case, this is how we get memory for malloc() */
  errno = 0;
  foo = mmap(0, 65536, PROT_READ|PROT_WRITE,
	     MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);

  printf("mmap() returned %p, errno = %d\n", foo, errno);

  return 0;
}
