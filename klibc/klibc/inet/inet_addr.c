/*
 * inet/inet_addr.c
 */

#include <arpa/inet.h>
#include <stdio.h>

uint32_t inet_addr(const char *str)
{
  struct in_addr a;
  int rv = inet_aton(str, &a);

  return rv ? INADDR_NONE : a.s_addr;
}
