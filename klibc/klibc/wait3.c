/*
 * wait3.c
 */

#include <sys/types.h>
#include <sys/resource.h>
#include <sys/wait.h>

pid_t wait3(int *status, int options, struct rusage *rusage)
{
  return wait4((pid_t)-1, status, options, rusage);
}
