/*
 * raise.c
 */

#include <unistd.h>
#include <signal.h>

int raise(int signal)
{
  return kill(getpid(), signal);
}
