/*
 * inet/inet_ntoa.c
 */

#include <arpa/inet.h>
#include <stdio.h>

char *inet_ntoa(struct in_addr addr)
{
  static char name[16];
  union {
    uint8_t  b[4];
    uint32_t l;
  } a;
  a.l = addr.s_addr;

  sprintf(name, "%u.%u.%u.%u", a.b[0], a.b[1], a.b[2], a.b[3]);
  return name;
}
