/*
 * send.c
 */

#include <stddef.h>
#include <sys/socket.h>

int send(int s, const void *buf, size_t len, unsigned int flags)
{
  return sendto(s, buf, len, flags, NULL, 0);
}
