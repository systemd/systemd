/*
 * fwrite2.c
 *
 * The actual fwrite() function as a non-inline
 */

#define __NO_FREAD_FWRITE_INLINES
#include <stdio.h>

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *f)
{
  return _fwrite(ptr, size*nmemb, f)/size;
}
