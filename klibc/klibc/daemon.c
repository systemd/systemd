/*
 * daemon.c - "daemonize" a process
 */

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

int daemon(int nochdir, int noclose)
{
  int nullfd;
  pid_t f;

  if ( !nochdir ) {
    if ( chdir("/") )
      return -1;
  }

  if ( !noclose ) {
    if ( (nullfd = open("/dev/null", O_RDWR)) < 0 ||
	 dup2(nullfd, 0) < 0 ||
	 dup2(nullfd, 1) < 0 ||
	 dup2(nullfd, 2) < 0 )
      return -1;
    close(nullfd);
  }
  
  f = fork();
  if ( f < 0 )
    return -1;
  else if ( f > 0 )
    _exit(0);


  return setsid();
}

  
