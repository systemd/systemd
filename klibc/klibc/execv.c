/*
 * execv.c
 */

#include <stdarg.h>
#include <unistd.h>

int execv(const char *path, char * const * argv)
{
  return execve(path, argv, environ);
}


