/*
 * atox.c
 *
 * atoi(), atol(), atoll()
 */

#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>

TYPE NAME (const char *nptr)
{
  return (TYPE) strntoumax(nptr, (char **)NULL, 10, ~(size_t)0);
}
