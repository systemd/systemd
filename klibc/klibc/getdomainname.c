/*
 * getdomainname.c
 */

#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/utsname.h>

int getdomainname(char *name, size_t len)
{
  struct utsname un;

  if ( !uname(&un) )
    return -1;

  if ( len < strlen(un.domainname)+1 ) {
    errno = EINVAL;
    return -1;
  }

  strcpy(name, un.domainname);

  return 0;
}
