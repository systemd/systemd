/*
 * waitpid.c
 */

#include <sys/types.h>
#include <sys/resource.h>
#include <sys/wait.h>

pid_t waitpid(pid_t pid, int *status, int options)
{
  return wait4(pid, status, options, NULL);
}
