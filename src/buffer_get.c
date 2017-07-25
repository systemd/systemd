/* Public domain. */

#include "buffer.h"
#include "byte.h"
#include "error.h"

static int oneread(int (*op)(),int fd,char *buf,unsigned int len)
{
  int r;

  for (;;) {
    r = op(fd,buf,len);
    if (r == -1) if (errno == error_intr) continue;
    return r;
  }
}

static int getthis(buffer *s,char *buf,unsigned int len)
{
  if (len > s->p) len = s->p;
  s->p -= len;
  byte_copy(buf,len,s->x + s->n);
  s->n += len;
  return len;
}

int buffer_feed(buffer *s)
{
  int r;

  if (s->p) return s->p;
  r = oneread(s->op,s->fd,s->x,s->n);
  if (r <= 0) return r;
  s->p = r;
  s->n -= r;
  if (s->n > 0) byte_copyr(s->x + s->n,r,s->x);
  return r;
}

int buffer_bget(buffer *s,char *buf,unsigned int len)
{
  int r;
 
  if (s->p > 0) return getthis(s,buf,len);
  if (s->n <= len) return oneread(s->op,s->fd,buf,s->n);
  r = buffer_feed(s); if (r <= 0) return r;
  return getthis(s,buf,len);
}

int buffer_get(buffer *s,char *buf,unsigned int len)
{
  int r;
 
  if (s->p > 0) return getthis(s,buf,len);
  if (s->n <= len) return oneread(s->op,s->fd,buf,len);
  r = buffer_feed(s); if (r <= 0) return r;
  return getthis(s,buf,len);
}

char *buffer_peek(buffer *s)
{
  return s->x + s->n;
}

void buffer_seek(buffer *s,unsigned int len)
{
  s->n += len;
  s->p -= len;
}
