/*
 * seteuid.c
 */

#include <unistd.h>

int seteuid(uid_t euid)
{
  return setreuid(-1, euid);
}
