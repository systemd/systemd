/*
 * execvp.c
 */

#include <stdarg.h>
#include <unistd.h>

int execvp(const char *path, char * const * argv)
{
  return execvpe(path, argv, environ);
}


