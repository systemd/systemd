/*
 * inet/inet_pton.c
 */

#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in6.h>

static inline int hexval(int ch)
{
  if ( ch >= '0' && ch <= '9' ) {
    return ch-'0';
  } else if ( ch >= 'A' && ch <= 'F' ) {
    return ch-'A'+10;
  } else if ( ch >= 'a' && ch <= 'f' ) {
    return ch-'a'+10;
  } else {
    return -1;
  }
}

int inet_pton(int af, const char *src, void *dst)
{
  switch ( af ) {
  case AF_INET:
    return inet_aton(src, (struct in_addr *)dst);
    
  case AF_INET6:
    {
      struct in6_addr *d = (struct in6_addr *)dst;
      int colons = 0, dcolons = 0;
      int i;
      const char *p;

      /* A double colon will increment colons by 2, dcolons by 1 */
      for ( p = dst ; *p ; p++ ) {
	if ( p[0] == ':' ) {
	  colons++;
	  if ( p[1] == ':' )
	    dcolons++;
	} else if ( !isxdigit(*p) )
	  return 0;		/* Not a valid address */
      }

      if ( colons > 7 || dcolons > 1 || (!dcolons && colons != 7) )
	return 0;		/* Not a valid address */

      memset(d, 0, sizeof(struct in6_addr));

      i = 0;
      for ( p = dst ; *p ; p++ ) {
	if ( *p == ':' ) {
	  if ( p[1] == ':' ) {
	    i += (8-colons);
	  } else {
	    i++;
	  }
	} else {
	  d->s6_addr16[i] = htons((ntohs(d->s6_addr16[i]) << 4) + hexval(*p));
	}
      }

      return 1;
    }

  default:
    errno = EAFNOSUPPORT;
    return -1;
  }
}
