/*
 * assert.c
 */

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

void __assert_fail(const char *expr, const char *file, unsigned int line)
{
  printf("Assertion %s failed, file %s, line %u\n", expr, file, line);
  abort();
}
