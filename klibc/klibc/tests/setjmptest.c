/*
 * setjmptest.c
 */

#include <stdio.h>
#include <setjmp.h>

static jmp_buf buf;

void do_stuff(int v)
{
  printf("setjmp returned %d\n", v);
  longjmp(buf, v+1);
}

void recurse(int ctr, int v)
{
  if ( ctr-- ) {
    recurse(ctr, v);
  } else {
    do_stuff(v);
  }
  _fwrite(".", 1, stdout);
}

int main(void)
{
  int v;

  v = setjmp(buf);

  if ( v < 256 )
    recurse(v,v);

  return 0;
}
