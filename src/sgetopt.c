/* Public domain. */

/* sgetopt.c, sgetopt.h: (yet another) improved getopt clone, outer layer
D. J. Bernstein, djb@pobox.com.
Depends on subgetopt.h, buffer.h.
No system requirements.
19991219: Switched to buffer.h.
19970208: Cleanups.
931201: Baseline.
No known patent problems.

Documentation in sgetopt.3.
*/

#include "buffer.h"
#define SGETOPTNOSHORT
#include "sgetopt.h"
#define SUBGETOPTNOSHORT
#include "subgetopt.h"

#define getopt sgetoptmine
#define optind subgetoptind
#define opterr sgetopterr
#define optproblem subgetoptproblem
#define optprogname sgetoptprogname

int opterr = 1;
const char *optprogname = 0;

int getopt(int argc,const char *const *argv,const char *opts)
{
  int c;
  const char *s;

  if (!optprogname) {
    optprogname = *argv;
    if (!optprogname) optprogname = "";
    for (s = optprogname;*s;++s) if (*s == '/') optprogname = s + 1;
  }
  c = subgetopt(argc,argv,opts);
  if (opterr)
    if (c == '?') {
      char chp[2]; chp[0] = optproblem; chp[1] = '\n';
      buffer_puts(buffer_2,optprogname);
      if (argv[optind] && (optind < argc))
        buffer_puts(buffer_2,": illegal option -- ");
      else
        buffer_puts(buffer_2,": option requires an argument -- ");
      buffer_put(buffer_2,chp,2);
      buffer_flush(buffer_2);
    }
  return c;
}
