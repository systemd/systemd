/*
 * perror.c
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

void perror(const char *s)
{
  fprintf(stderr, "%s: error %d\n", s, errno);
}
