/*
 * recv.c
 */

#include <stddef.h>
#include <sys/socket.h>

int recv(int s, void *buf, size_t len, unsigned int flags)
{
  return recvfrom(s, buf, len, flags, NULL, 0);
}
