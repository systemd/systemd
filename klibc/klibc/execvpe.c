/*
 * execvpe.c
 *
 * execvpe() function (from which we build execlp, execlpe, execvp).
 *
 * This version of execvpe() will *not* spawn /bin/sh if the command
 * return ENOEXEC.  That's what #! is for, folks!
 *
 * Since execlpe() and execvpe() aren't in POSIX, nor in glibc,
 * I have followed QNX precedent in the implementation of the PATH:
 * the PATH that is used is the one in the current environment, not
 * in the new environment.
 */

#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#define DEFAULT_PATH 	"/bin:/usr/bin:."

int execvpe(const char *file, char * const *argv, char * const *envp)
{
  char path[PATH_MAX];
  const char *searchpath, *esp;
  size_t prefixlen, filelen, totallen;

  if ( strchr(file, '/') )	/* Specific path */
    return execve(file, argv, envp);

  filelen = strlen(file);

  searchpath = getenv("PATH");
  if ( !searchpath )
    searchpath = DEFAULT_PATH;
  
  errno = ENOENT; /* Default errno, if execve() doesn't change it */

  do {
    esp = strchr(searchpath, ':');
    if ( esp )
      prefixlen = esp-searchpath;
    else
      prefixlen = strlen(searchpath);
    
    if ( prefixlen == 0 || searchpath[prefixlen-1] == '/' ) {
      totallen = prefixlen+filelen;
      if ( totallen >= PATH_MAX )
	continue;
      memcpy(path, searchpath, prefixlen);
      memcpy(path+prefixlen, file, filelen);
    } else {
      totallen = prefixlen+filelen+1;
      if ( totallen >= PATH_MAX )
	continue;
      memcpy(path, searchpath, prefixlen);
      path[prefixlen] = '/';
      memcpy(path+prefixlen+1, file, filelen);
    }
    path[totallen] = '\0';
    
    execve(path, argv, envp);
    if ( errno == E2BIG || errno == ENOEXEC ||
	 errno == ENOMEM || errno == ETXTBSY )
      break;			/* Report this as an error, no more search */
    
    searchpath = esp+1;
  } while ( esp );

  return -1;
}

