/*
 * fwrite.c
 */

#include <errno.h>
#include <unistd.h>
#include <stdio.h>

size_t _fwrite(const void *buf, size_t count, FILE *f)
{
  size_t bytes = 0;
  ssize_t rv;
  const char *p = buf;

  while ( count ) {
    rv = write(fileno(f), p, count);
    if ( rv == -1 ) {
      if ( errno == EINTR )
	continue;
      else
	break;
    } else if ( rv == 0 ) {
      break;
    }

    p += rv;
    bytes += rv;
    count -= rv;
  }

  return bytes;
}

    
      
