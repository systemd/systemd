/*
 * calloc.c
 */

#include <stdlib.h>
#include <string.h>

/* FIXME: This should look for multiplication overflow */

void *calloc(size_t nmemb, size_t size)
{
  void *ptr;

  size *= nmemb;
  ptr = malloc(size);
  if ( ptr )
    memset(ptr, 0, size);

  return ptr;
}

