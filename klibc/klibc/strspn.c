/*
 * strspn
 */

#include "strxspn.h"

size_t
strspn(const char *s, const char *accept)
{
  return __strxspn(s, accept, 0);
}
