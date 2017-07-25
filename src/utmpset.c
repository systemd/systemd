#include <fcntl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include "uw_tmp.h"
#include "strerr.h"
#include "sgetopt.h"
#include "seek.h"
#include "str.h"
#include "open.h"
#include "byte.h"
#include "lock.h"

#define USAGE " [-w] line"
#define FATAL "utmpset: fatal: "
#define WARNING "utmpset: warning: "

const char *progname;

void usage(void) { strerr_die4x(1, "usage: ", progname, USAGE, "\n"); }

int utmp_logout(const char *line) {
  int fd;
  uw_tmp ut;
  int ok =-1;

  if ((fd =open(UW_TMP_UFILE, O_RDWR, 0)) < 0)
    strerr_die4sys(111, FATAL, "unable to open ", UW_TMP_UFILE, ": ");
  if (lock_ex(fd) == -1)
    strerr_die4sys(111, FATAL, "unable to lock: ", UW_TMP_UFILE, ": ");

  while (read(fd, &ut, sizeof(uw_tmp)) == sizeof(uw_tmp)) {
    if (!ut.ut_name[0] || (str_diff(ut.ut_line, line) != 0)) continue;
    memset(ut.ut_name, 0, sizeof ut.ut_name);
    memset(ut.ut_host, 0, sizeof ut.ut_host);
    if (time(&ut.ut_time) == -1) break;
#ifdef DEAD_PROCESS
    ut.ut_type =DEAD_PROCESS;
#endif
    if (lseek(fd, -(off_t)sizeof(uw_tmp), SEEK_CUR) == -1) break;
    if (write(fd, &ut, sizeof(uw_tmp)) != sizeof(uw_tmp)) break;
    ok =1;
    break;
  }
  close(fd);
  return(ok);
}
int wtmp_logout(const char *line) {
  int fd;
  int len;
  struct stat st;
  uw_tmp ut;

  if ((fd = open_append(UW_TMP_WFILE)) == -1)
    strerr_die4sys(111, FATAL, "unable to open ", UW_TMP_WFILE, ": ");
  if (lock_ex(fd) == -1)
    strerr_die4sys(111, FATAL, "unable to lock ", UW_TMP_WFILE, ": ");

  if (fstat(fd, &st) == -1) {
    close(fd);
    return(-1);
  }
  memset(&ut, 0, sizeof(uw_tmp));
  if ((len =str_len(line)) > sizeof ut.ut_line) len =sizeof ut.ut_line -2;
  byte_copy(ut.ut_line, len, line);
  if (time(&ut.ut_time) == -1) {
    close(fd);
    return(-1);
  }
#ifdef DEAD_PROCESS
  ut.ut_type =DEAD_PROCESS;
#endif
  if (write(fd, &ut, sizeof(uw_tmp)) != sizeof(uw_tmp)) {
    ftruncate(fd, st.st_size);
    close(fd);
    return(-1);
  }
  close(fd);
  return(1);
}

int main (int argc, const char * const *argv, const char * const *envp) {
  int opt;
  int wtmp =0;

  progname =*argv;

  while ((opt =getopt(argc, argv, "wV")) != opteof) {
    switch(opt) {
    case 'w':
      wtmp =1;
      break;
    case 'V':
      strerr_warn1("$Id: cb399098f794012a7f5e6a3a7090b2d53b86c08c $", 0);
    case '?':
      usage();
    }
  }
  argv +=optind;

  if (! argv || ! *argv) usage();
  if (utmp_logout(*argv) == -1)
    strerr_die4x(111, WARNING, "unable to logout line ", *argv,
                 " in utmp: no such entry");
  if (wtmp)
    if (wtmp_logout(*argv) == -1)
      strerr_die4sys(111, WARNING,
                     "unable to logout line ", *argv, " in wtmp: ");
  _exit(0);
}
