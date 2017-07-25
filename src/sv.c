#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "str.h"
#include "strerr.h"
#include "error.h"
#include "sgetopt.h"
#include "open.h"
#include "env.h"
#include "buffer.h"
#include "fmt.h"
#include "scan.h"
#include "tai.h"
#include "taia.h"
#include "wait.h"

#define USAGE " [-v] [-w sec] command service ..."
#define USAGELSB " [-w sec] command"

#define VERSION "$Id: 900314260c6d52c986c5357673bea2f3bd3f4698 $"

#define FATAL   "fatal: "
#define FAIL    "fail: "
#define WARN    "warning: "
#define OK      "ok: "
#define RUN     "run: "
#define FINISH  "finish: "
#define DOWN    "down: "
#define TIMEOUT "timeout: "
#define KILL    "kill: "

char *progname;
char *action;
char *acts;
char *varservice ="/service/";
char **service;
char **servicex;
unsigned int services;
unsigned int rc =0;
unsigned int lsb;
unsigned int verbose =0;
unsigned long wait =7;
unsigned int kll =0;
unsigned int islog =0;
struct taia tstart, tnow, tdiff;
struct tai tstatus;

int (*act)(char*) =0;
int (*cbk)(char*) =0;

int curdir, fd, r;
char svstatus[20];
char sulong[FMT_ULONG];

void usage() {
  if (!lsb) strerr_die4x(100, "usage: ", progname, USAGE, "\n");
  strerr_die4x(2, "usage: ", progname, USAGELSB, "\n");
}
void done(unsigned int e) { if (curdir != -1) fchdir(curdir); _exit(e); }
void fatal(char *m1) {
  strerr_warn3(FATAL, m1, ": ", &strerr_sys);
  done(lsb ? 151 : 100);
}
void fatal2(char *m1, char *m2) {
  strerr_warn4(FATAL, m1, m2, ": ", &strerr_sys);
  done(lsb ? 151 : 100);
}
void out(char *p, char *m1) {
  buffer_puts(buffer_1, p);
  buffer_puts(buffer_1, *service);
  if (islog) buffer_puts(buffer_1, "/log");
  buffer_puts(buffer_1, ": ");
  buffer_puts(buffer_1, m1);
  if (errno) {
    buffer_puts(buffer_1, ": ");
    buffer_puts(buffer_1, error_str(errno));
  }
  buffer_puts(buffer_1, "\n");
  buffer_flush(buffer_1);
}
void fail(char *m1) { ++rc; out(FAIL, m1); }
void failx(char *m1) { errno =0; fail(m1); }
void warn(char *m1) { ++rc; out(WARN, m1); }
void warnx(char *m1) { errno =0; warn(m1); }
void ok(char *m1) { errno =0; out(OK, m1); }

void outs(const char *s) { buffer_puts(buffer_1, s); }
void flush(const char *s) { outs(s); buffer_flush(buffer_1); }
void outs2(const char *s) { buffer_puts(buffer_2, s); }
void flush2(const char *s) { outs2(s); buffer_flush(buffer_2); }

int svstatus_get() {
  if ((fd =open_write("supervise/ok")) == -1) {
    if (errno == error_nodevice) {
      *acts == 'x' ? ok("runsv not running") : failx("runsv not running");
      return(0);
    }
    warn("unable to open supervise/ok");
    return(-1);
  }
  close(fd);
  if ((fd =open_read("supervise/status")) == -1) {
    warn("unable to open supervise/status");
    return(-1);
  }
  r =read(fd, svstatus, 20);
  close(fd);
  switch(r) {
  case 20: break;
  case -1: warn("unable to read supervise/status"); return(-1);
  default: warnx("unable to read supervise/status: bad format"); return(-1);
  }
  return(1);
}
unsigned int svstatus_print(char *m) {
  int pid;
  int normallyup =0;
  struct stat s;
 
  if (stat("down", &s) == -1) {
    if (errno != error_noent) {
      outs2(WARN); outs2("unable to stat "); outs2(*service); outs2("/down: ");
      outs2(error_str(errno)); flush2("\n");
      return(0);
    }
    normallyup =1;
  }
  pid =(unsigned char) svstatus[15];
  pid <<=8; pid +=(unsigned char)svstatus[14];
  pid <<=8; pid +=(unsigned char)svstatus[13];
  pid <<=8; pid +=(unsigned char)svstatus[12];
  tai_unpack(svstatus, &tstatus);
  switch (svstatus[19]) {
  case 0: outs(DOWN); break;
  case 1: outs(RUN); break;
  case 2: outs(FINISH); break;
  }
  outs(m); outs(": ");
  if (svstatus[19]) {
    outs("(pid "); sulong[fmt_ulong(sulong, pid)] =0;
    outs(sulong); outs(") ");
  }
  buffer_put(buffer_1, sulong,
    fmt_ulong(sulong, tnow.sec.x < tstatus.x ? 0 : tnow.sec.x -tstatus.x));
  outs("s");
  if (pid && !normallyup) outs(", normally down");
  if (!pid && normallyup) outs(", normally up");
  if (pid && svstatus[16]) outs(", paused");
  if (!pid && (svstatus[17] == 'u')) outs(", want up");
  if (pid && (svstatus[17] == 'd')) outs(", want down");
  if (pid && svstatus[18]) outs(", got TERM");
  return(pid ? 1 : 2);
}
int status(char *unused) {
  int rc;

  rc =svstatus_get();
  switch(rc) { case -1: if (lsb) done(4); case 0: return(0); }
  rc =svstatus_print(*service);
  islog =1;
  if (chdir("log") == -1) {
    if (errno != error_noent) {
      outs("; ");
      warn("unable to change directory");
    }
    else outs("\n");
  }
  else {
    outs("; ");
    if (svstatus_get()) { rc =svstatus_print("log"); outs("\n"); }
  }
  islog =0;
  flush("");
  if (lsb) switch(rc) { case 1: done(0); case 2: done(3); case 0: done(4); }
  return(rc);
}

int checkscript() {
  char *prog[2];
  struct stat s;
  int pid, w;

  if (stat("check", &s) == -1) {
    if (errno == error_noent) return(1);
    outs2(WARN); outs2("unable to stat "); outs2(*service); outs2("/check: ");
    outs2(error_str(errno)); flush2("\n");
    return(0);
  }
  /* if (!(s.st_mode & S_IXUSR)) return(1); */
  if ((pid =fork()) == -1) {
    outs2(WARN); outs2("unable to fork for "); outs2(*service);
    outs2("/check: "); outs2(error_str(errno)); flush2("\n");
    return(0);
  }
  if (!pid) {
    prog[0] ="./check";
    prog[1] =0;
    close(1);
    execve("check", prog, environ);
    outs2(WARN); outs2("unable to run "); outs2(*service); outs2("/check: ");
    outs2(error_str(errno)); flush2("\n");
    _exit(0);
  }
  while (wait_pid(&w, pid) == -1) {
    if (errno == error_intr) continue;
    outs2(WARN); outs2("unable to wait for child "); outs2(*service);
    outs2("/check: "); outs2(error_str(errno)); flush2("\n");
    return(0);
  }
  return(!wait_exitcode(w));
}

int check(char *a) {
  unsigned int pid;

  if ((r =svstatus_get()) == -1) return(-1);
  while (*a) {
    if (r == 0) { if (*a == 'x') return(1); return(-1); }
    pid =(unsigned char)svstatus[15];
    pid <<=8; pid +=(unsigned char)svstatus[14];
    pid <<=8; pid +=(unsigned char)svstatus[13];
    pid <<=8; pid +=(unsigned char)svstatus[12];
    switch (*a) {
    case 'x': return(0);
    case 'u':
      if (!pid || svstatus[19] != 1) return(0);
      if (!checkscript()) return(0);
      break;
    case 'd': if (pid || svstatus[19] != 0) return(0); break;
    case 'C': if (pid) if (!checkscript()) return(0); break;
    case 't':
    case 'k':
      if (!pid && svstatus[17] == 'd') break;
      tai_unpack(svstatus, &tstatus);
      if ((tstart.sec.x > tstatus.x) || !pid || svstatus[18] || !checkscript())
        return(0);
      break;
    case 'o':
      tai_unpack(svstatus, &tstatus);
      if ((!pid && tstart.sec.x > tstatus.x) || (pid && svstatus[17] != 'd'))
        return(0);
      break;
    case 'p': if (pid && !svstatus[16]) return(0); break;
    case 'c': if (pid && svstatus[16]) return(0); break;
    }
    ++a;
  }
  outs(OK); svstatus_print(*service); flush("\n");
  return(1);
}
int control(char *a) {
  if (svstatus_get() <= 0) return(-1);
  if (svstatus[17] == *a)
    if (*a != 'd' || svstatus[18] == 1) return(0); /* once w/o term */
  if ((fd =open_write("supervise/control")) == -1) {
    if (errno != error_nodevice)
      warn("unable to open supervise/control");
    else
      *a == 'x' ? ok("runsv not running") : failx("runsv not running");
    return(-1);
  }
  r =write(fd, a, str_len(a));
  close(fd);
  if (r != str_len(a)) {
    warn("unable to write to supervise/control");
    return(-1);
  }
  return(1);
}

int main(int argc, char **argv) {
  unsigned int i, done;
  char *x;

  progname =*argv;
  for (i =str_len(*argv); i; --i) if ((*argv)[i -1] == '/') break;
  *argv +=i;
  optprogname =progname =*argv;
  service =argv;
  services =1;
  lsb =(str_diff(progname, "sv"));
  if ((x =env_get("SVDIR"))) varservice =x;
  if ((x =env_get("SVWAIT"))) scan_ulong(x, &wait);
  while ((i =getopt(argc, (const char* const*)argv, "w:vV")) != opteof) {
    switch(i) {
    case 'w': scan_ulong(optarg, &wait);
    case 'v': verbose =1; break;
    case 'V': strerr_warn1(VERSION, 0);
    case '?': usage();
    }
  }
  argv +=optind; argc -=optind;
  if (!(action =*argv++)) usage(); --argc;
  if (!lsb) { service =argv; services =argc; }
  if (!*service) usage();

  taia_now(&tnow); tstart =tnow;
  if ((curdir =open_read(".")) == -1)
    fatal("unable to open current directory");

  act =&control; acts ="s";
  if (verbose) cbk =&check;
  switch (*action) {
  case 'x': case 'e':
    acts ="x"; break;
  case 'X': case 'E':
    acts ="x"; kll =1; cbk =&check; break;
  case 'D':
    acts ="d"; kll =1; cbk =&check; break;
  case 'T':
    acts ="tc"; kll =1; cbk =&check; break;
  case 't':
    if (!str_diff(action, "try-restart")) { acts ="tc"; cbk =&check; break; }
  case 'c':
    if (!str_diff(action, "check")) { act =0; acts ="C"; cbk =&check; break; }
  case 'u': case 'd': case 'o': case 'p': case 'h':
  case 'a': case 'i': case 'k': case 'q': case '1': case '2':
    action[1] =0; acts =action; break;
  case 's':
    if (!str_diff(action, "shutdown")) { acts ="x"; cbk =&check; break; }
    if (!str_diff(action, "start")) { acts ="u"; cbk =&check; break; }
    if (!str_diff(action, "stop")) { acts ="d"; cbk =&check; break; }
    if (lsb && str_diff(action, "status")) usage();
    act =&status; cbk =0; break;
  case 'r':
    if (!str_diff(action, "restart")) { acts ="tcu"; cbk =&check; break; }
    if (!str_diff(action, "reload")) { acts ="h"; cbk =&check; break; }
    usage();
  case 'f':
    if (!str_diff(action, "force-reload"))
      { acts ="tc"; kll =1; cbk =&check; break; }
    if (!str_diff(action, "force-restart"))
      { acts ="tcu"; kll =1; cbk =&check; break; }
    if (!str_diff(action, "force-shutdown"))
      { acts ="x"; kll =1; cbk =&check; break; }
    if (!str_diff(action, "force-stop"))
      { acts ="d"; kll =1; cbk =&check; break; }
  default:
    usage();
  }

  servicex =service;
  for (i =0; i < services; ++i) {
    if ((**service != '/') && (**service != '.') && **service &&
        ((*service)[str_len(*service) -1] != '/')) {
      if ((chdir(varservice) == -1) || (chdir(*service) == -1)) {
        fail("unable to change to service directory");
        *service =0;
      }
    }
    else
      if (chdir(*service) == -1) {
        fail("unable to change to service directory");
        *service =0;
      }
    if (*service) if (act && (act(acts) == -1)) *service =0;
    if (fchdir(curdir) == -1) fatal("unable to change to original directory");
    service++;
  }

  if (*cbk)
    for (;;) {
      taia_sub(&tdiff, &tnow, &tstart);
      service =servicex; done =1;
      for (i =0; i < services; ++i, ++service) {
        if (!*service) continue;
        if ((**service != '/') && (**service != '.')) {
          if ((chdir(varservice) == -1) || (chdir(*service) == -1)) {
            fail("unable to change to service directory");
            *service =0;
          }
        }
        else
          if (chdir(*service) == -1) {
            fail("unable to change to service directory");
            *service =0;
          }
        if (*service) { if (cbk(acts) != 0) *service =0; else done =0; }
        if (*service && taia_approx(&tdiff) > wait) {
          kll ? outs(KILL) : outs(TIMEOUT);
          if (svstatus_get() > 0) { svstatus_print(*service); ++rc; }
          flush("\n");
          if (kll) control("k");
          *service =0;
        }
        if (fchdir(curdir) == -1)
          fatal("unable to change to original directory");
      }
      if (done) break;
      usleep(420000);
      taia_now(&tnow);
    }
  return(rc > 99 ? 99 : rc);
}
