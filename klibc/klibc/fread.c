/*
 * fread.c
 */

#include <errno.h>
#include <unistd.h>
#include <stdio.h>

size_t _fread(void *buf, size_t count, FILE *f)
{
  size_t bytes = 0;
  ssize_t rv;
  char *p = buf;

  while ( count ) {
    rv = read(fileno(f), p, count);
    if ( rv == -1 ) {
      if ( errno == EINTR ) {
	errno = 0;
	continue;
      } else
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

    
      
