/*
 * strcspn
 */

#include "strxspn.h"

size_t
strcspn(const char *s, const char *reject)
{
  return __strxspn(s, reject, 1);
}
