#include <unistd.h>
#include "strerr.h"
#include "error.h"
#include "sgetopt.h"
#include "scan.h"
#include "open.h"
#include "tai.h"
#include "buffer.h"
#include "fmt.h"

#define FATAL "svwaitup: fatal: "
#define WARN "svwaitup: warning: "
#define INFO "svwaitup: "
#define USAGE " [-v] [-s 1..600] service ..."

const char *progname;
unsigned long sec =2;
unsigned int rc =0;
const char * const *dir;

void fatal(const char *m) { strerr_die3sys(111, FATAL, m, ": "); }
void warn(const char *s1, const char *s2, struct strerr *e) {
  dir++; rc++;
  strerr_warn3(WARN, s1, s2, e);
}
void usage() { strerr_die4x(1, "usage: ", progname, USAGE, "\n"); }

int main(int argc, const char * const *argv) {
  int opt;
  int verbose =0;
  char status[18];
  int fd;
  int is;
  int r;
  int wdir;
  unsigned long pid;
  struct tai when;
  struct tai now;
  char sulong[FMT_ULONG];

  progname =*argv;
  
  while ((opt =getopt(argc, argv, "s:vV")) != opteof) {
    switch(opt) {
    case 's': 
      scan_ulong(optarg, &sec);
      if ((sec < 1) || (sec > 600)) usage();
      break;
    case 'v':
      verbose =1;
      break;
    case 'V':
      strerr_warn1("$Id: e2d6c574c5e56f9931323fbc0e539c7f9b829b73 $", 0);
    case '?':
      usage();
    }
  }
  argv +=optind;
  if (! argv || ! *argv) usage();

  if ((wdir =open_read(".")) == -1)
    fatal("unable to open current working directory");

  dir =argv;
  while (*dir) {
    if (dir != argv)
      if (fchdir(wdir) == -1) fatal("unable to switch to starting directory");
    if (chdir(*dir) == -1) {
      warn(*dir, ": unable to change directory: ", &strerr_sys);
      continue;
    }
    if ((fd =open_write("supervise/ok")) == -1) {
      if (errno == error_nodevice)
        warn(*dir, ": runsv not running.", 0);
      else
        warn(*dir, ": unable to open supervise/ok: ", &strerr_sys);
      continue;
    }
    close(fd);
    
    if ((fd =open_read("supervise/status")) == -1) {
      warn(*dir, "unable to open supervise/status: ", &strerr_sys);
      continue;
    }
    r =buffer_unixread(fd, status, sizeof status);
    close(fd);
    if (r < sizeof status) {
      if (r == -1)
        warn(*dir, "unable to read supervise/status: ", &strerr_sys);
      else
        warn(*dir, ": unable to read supervise/status: bad format.", 0);
      continue;
    }
    
    pid =(unsigned char)status[15];
    pid <<=8; pid +=(unsigned char)status[14];
    pid <<=8; pid +=(unsigned char)status[13];
    pid <<=8; pid +=(unsigned char)status[12];
    if (! pid) {
      warn(*dir, ": is down.", 0);
      continue;
    }
    
    tai_unpack(status, &when);
    tai_now(&now);
    if (tai_less(&now, &when)) when =now;
    tai_sub(&when, &now, &when);
    is =tai_approx(&when);
    
    if (is >= sec) {
      /* ok */
      if (verbose) {
        sulong[fmt_ulong(sulong, is)] =0;
        strerr_warn5(INFO, *dir, ": is up (", sulong, " seconds)", 0);
      }
      dir++;
      continue;
    }
    sleep(sec -is);
  }
  if (fchdir(wdir) == -1) 
    strerr_warn2(WARN, "unable to switch to starting directory: ", &strerr_sys);
  close(wdir);
  if (rc > 100) rc =100;
  _exit(rc);
}
