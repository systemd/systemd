#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "strerr.h"
#include "error.h"
#include "sgetopt.h"
#include "open.h"
#include "buffer.h"
#include "tai.h"
#include "fmt.h"

#define USAGE " [ -l ] service ..."

#define VERSION "$Id: c17bbd3eda6f3c57027dfb47ff676bdd3fefff9f $"

#define FATAL "runsvstat: fatal: "
#define WARNING "runsvstat: warning: "

const char *progname;
unsigned int rc =0;
struct stat s;
int showlog =0;

void usage() { strerr_die4x(1, "usage: ", progname, USAGE, "\n"); }

void fatal(char *m1) { strerr_die3sys(111, FATAL, m1, ": "); }
void warn(char *m1, char *m2) {
  rc++;
  strerr_warn5(WARNING, m1, ": ", m2, ": ", &strerr_sys);
}
void warnx(char *m1, char *m2) {
  rc++;
  strerr_warn4(WARNING, m1, ": ", m2, 0);
}

int show_status(char *name) {
  char status[20];
  int pid;
  int fd;
  int normallyup =0;
  char sulong[FMT_ULONG];
  struct tai when;
  struct tai now;

  if (stat("down", &s) == -1) {
    if (errno != error_noent) {
      warn(name, "unable to stat down");
      return(-1);
    }
    normallyup = 1;
  }
  if ((fd =open_write("supervise/ok")) == -1) {
    if (errno == error_nodevice)
      warnx(name, "runsv not running.");
    else
      warn(name, "unable to open supervise/ok");
    return(-1);
  }
  close(fd);
  if ((fd =open_read("supervise/status")) == -1) {
    warn(name, "unable to open supervise/status");
    return(-1);
  }
  switch(read(fd, status, 20)) {
  case 20: break;
  case -1:
    warn(name, "unable to read supervise/status");
    return(-1);
  default:
    warnx(name, "unable to read supervise/status: bad format.");
    return(-1);
  }
  pid =(unsigned char) status[15];
  pid <<=8; pid +=(unsigned char)status[14];
  pid <<=8; pid +=(unsigned char)status[13];
  pid <<=8; pid +=(unsigned char)status[12];

  tai_unpack(status,&when);
  tai_now(&now);
  if (tai_less(&now,&when)) when =now;
  tai_sub(&when,&now,&when);

  buffer_puts(buffer_1, name);
  buffer_puts(buffer_1, ": ");
  if (pid) {
    switch (status[19]) {
    case 1: buffer_puts(buffer_1, "run "); break;
    case 2: buffer_puts(buffer_1, "finish "); break;
    }
    buffer_puts(buffer_1, "(pid ");
    buffer_put(buffer_1, sulong, fmt_ulong(sulong, pid));
    buffer_puts(buffer_1, ") ");
  }
  else
    buffer_puts(buffer_1, "down ");
  buffer_put(buffer_1, sulong, fmt_ulong(sulong, tai_approx(&when)));
  buffer_puts(buffer_1, " seconds");
  if (pid && !normallyup) buffer_puts(buffer_1,", normally down");
  if (!pid && normallyup) buffer_puts(buffer_1,", normally up");
  if (pid && status[16]) buffer_puts(buffer_1,", paused");
  if (!pid && (status[17] == 'u')) buffer_puts(buffer_1,", want up");
  if (pid && (status[17] == 'd')) buffer_puts(buffer_1,", want down");
  if (pid && status[18]) buffer_puts(buffer_1, ", got TERM");
  /* buffer_putsflush(buffer_1, "\n"); */
  return(1);
}

int main(int argc, char **argv) {
  int opt;
  int curdir;
  char **dir;

  progname =*argv;

  while ((opt =getopt(argc, (const char * const *)argv, "lV")) != opteof) {
    switch(opt) {
    case 'l':
      showlog =1;
      break;
    case 'V':
      strerr_warn1(VERSION, 0);
    case '?':
      usage();
    }
  }
  argv +=optind;

  dir =argv;
  if (! dir || ! *dir) usage();

  if ((curdir =open_read(".")) == -1) {
    rc =100;
    fatal("unable to open current directory");
  }
  for (; dir && *dir; dir++) {
    if (chdir(*dir) == -1) {
      warn(*dir, "unable to change directory");
      continue;
    }
    if (show_status(*dir) == 1) {
      if (showlog) {
        if (stat("log", &s) == -1) {
          if (errno != error_noent)
            warn("unable to stat()", "./log");
        }
        else {
          if (! S_ISDIR(s.st_mode))
            warnx("./log", "not a directory.");
          else {
            if (chdir("log") == -1) {
              warn(*dir, "unable to change directory");
              continue;
            }
            show_status("\n  log");
          }
        }
      }
      buffer_puts(buffer_1, "\n"); buffer_flush(buffer_1);
    }
    if (fchdir(curdir) == -1) {
      rc =100;
      fatal("unable to change directory");
    }
  }
  if (rc > 100) rc =100;
  _exit(rc);
}
