/*
 * inet/inet_aton.c
 */

#include <arpa/inet.h>
#include <stdio.h>

int inet_aton(const char *str, struct in_addr *addr)
{
  union {
    uint8_t  b[4];
    uint32_t l;
  } a;

  if ( sscanf(str, "%hhu.%hhu.%hhu.%hhu", &a.b[0], &a.b[1], &a.b[2], &a.b[3]) == 4 ) {
    addr->s_addr = a.l;		/* Always in network byte order */
    return 1;
  } else {
    return 0;
  }
}

    
