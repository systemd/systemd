/*
 * setegid.c
 */

#include <unistd.h>

int setegid(gid_t egid)
{
  return setregid(-1, egid);
}
