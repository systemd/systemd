/*
 * atexit.c
 */

#include <stdlib.h>

int atexit(void (*fctn)(void))
{
  return on_exit((void (*)(int, void *))fctn, NULL);
}
