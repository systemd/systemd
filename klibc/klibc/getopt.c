/*
 * getopt.c
 *
 * Simple POSIX getopt(), no GNU extensions...
 */

#include <stdint.h>
#include <unistd.h>
#include <string.h>

char *optarg;
int optind = 1;
int opterr, optopt;
static const char *__optptr;

int getopt(int argc, char * const *argv, const char *optstring)
{
  const char *carg = argv[optind];
  const char *osptr;
  int opt;

  /* We don't actually need argc */
  (void)argc;

  /* First, eliminate all non-option cases */
  
  if ( !carg || carg[0] != '-' || !carg[1] ) {
    return -1;
  }

  if ( carg[1] == '-' && !carg[2] ) {
    optind++;
    return -1;
  }

  if ( (uintptr_t)(__optptr-carg) > (uintptr_t)strlen(carg) )
    __optptr = carg+1;	/* Someone frobbed optind, change to new opt. */

  opt = *__optptr++;

  if ( opt != ':' && (osptr = strchr(optstring, opt)) ) {
    if ( osptr[1] == ':' ) {
      if ( *__optptr ) {
	/* Argument-taking option with attached argument */
	optarg = (char *)__optptr;
	optind++;
      } else {
	/* Argument-taking option with non-attached argument */
	if ( argv[optind+1] ) {
	  optarg = (char *)argv[optind+1];
	  optind += 2;
	} else {
	  /* Missing argument */
	  return (optstring[0] == ':') ? ':' : '?';
	}
      }
      return opt;
    } else {
      /* Non-argument-taking option */
      /* __optptr will remember the exact position to resume at */
      if ( ! *__optptr )
	optind++;
      return opt;
    }
  } else {
    /* Unknown option */
    optopt = opt;
    if ( ! *__optptr )
      optind++;
    return '?';
  }
}

	
