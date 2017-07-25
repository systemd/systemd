#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <sys/time.h>
#include <dirent.h>
#include <unistd.h>
#include <stdio.h>
#include "pmatch.h"
#include "fmt_ptime.h"
#include "alloc.h"
#include "stralloc.h"
#include "strerr.h"
#include "buffer.h"
#include "sig.h"
#include "env.h"
#include "fd.h"
#include "wait.h"
#include "error.h"
#include "sgetopt.h"
#include "open.h"
#include "openreadclose.h"
#include "coe.h"
#include "lock.h"
#include "str.h"
#include "byte.h"
#include "scan.h"
#include "direntry.h"
#include "taia.h"
#include "fmt.h"
#include "ndelay.h"
#include "iopause.h"

#define USAGE " [-ttv] [-r c] [-R abc] [-l len] [-b buflen] dir ..."
#define VERSION "$Id: 5e55a90e0a1b35ec47fed3021453c50675ea1117 $"

#define FATAL "svlogd: fatal: "
#define WARNING "svlogd: warning: "
#define PAUSE "svlogd: pausing: "
#define INFO "svlogd: info: "

const char *progname;

unsigned int verbose =0;
unsigned int timestamp =0;
unsigned long linemax =1000;
unsigned long buflen =1024;
unsigned long linelen;

const char *replace ="";
char repl =0;

const char **fndir;
int fdwdir;
struct stat st;
stralloc sa;
int wstat;
struct taia now;
struct taia trotate;

char *databuf;
buffer data;
char *line;
char stamp[FMT_PTIME];
unsigned int exitasap =0;
unsigned int rotateasap =0;
unsigned int reopenasap =0;
unsigned int linecomplete =1;
unsigned int tmaxflag =0;
int fdudp =-1;
iopause_fd in;

struct logdir {
  int fddir;
  char *btmp;
  buffer b;
  stralloc inst;
  unsigned long size;
  unsigned long sizemax;
  unsigned long nmax;
  unsigned long nmin;
  unsigned long tmax;
  struct taia trotate;
  stralloc processor;
  int ppid;
  char fnsave[FMT_PTIME];
  char *name;
  int fdcur;
  int fdlock;
  char match;
  char matcherr;
  struct sockaddr_in udpaddr;
  unsigned int udponly;
  stralloc prefix;
} *dir;
unsigned int dirn =0;

void usage() { strerr_die4x(111, "usage: ", progname, USAGE, "\n"); }
void die_nomem() { strerr_die2x(111, FATAL, "out of memory."); }
void fatal(char *m0) { strerr_die3sys(111, FATAL, m0, ": "); }
void fatalx(char *m0) { strerr_die2x(111, FATAL, m0); }
void fatal2(char *m0, char *m1) {
  strerr_die5sys(111, FATAL, m0, ": ", m1, ": ");
}
void warn(char *m0) { strerr_warn3(WARNING, m0, ": ", &strerr_sys); }
void warn2(char *m0, char *m1) {
  strerr_warn5(WARNING, m0, ": ", m1, ": ", &strerr_sys);
}
void warnx(char *m0, char *m1) { strerr_warn4(WARNING, m0, ": ", m1, 0); }
void pause_nomem() { strerr_warn2(PAUSE, "out of memory.", 0); sleep(3); }
void pause1(char *m0) { strerr_warn3(PAUSE, m0, ": ", &strerr_sys); sleep(3); }
void pause2(char *m0, char *m1) {
  strerr_warn5(PAUSE, m0, ": ", m1, ": ", &strerr_sys);
  sleep(3);
}

unsigned int processorstart(struct logdir *ld) {
  int pid;

  if (! ld->processor.len) return(0);
  if (ld->ppid) {
    warnx("processor already running", ld->name);
    return(0);
  }
  while ((pid =fork()) == -1)
    pause2("unable to fork for processor", ld->name);
  if (! pid) {
    char *prog[4];
    int fd;

    /* child */
    sig_uncatch(sig_term);
    sig_uncatch(sig_alarm);
    sig_uncatch(sig_hangup);
    sig_unblock(sig_term);
    sig_unblock(sig_alarm);
    sig_unblock(sig_hangup);
    
    if (verbose)
      strerr_warn5(INFO, "processing: ", ld->name, "/", ld->fnsave, 0);
    if ((fd =open_read(ld->fnsave)) == -1)
      fatal2("unable to open input for processor", ld->name);
    if (fd_move(0, fd) == -1)
      fatal2("unable to move filedescriptor for processor", ld->name);
    ld->fnsave[26] ='t';
    if ((fd =open_trunc(ld->fnsave)) == -1)
      fatal2("unable to open output for processor", ld->name);
    if (fd_move(1, fd) == -1)
      fatal2("unable to move filedescriptor for processor", ld->name);
    if ((fd =open_read("state")) == -1) {
      if (errno == error_noent) {
        if ((fd =open_trunc("state")) == -1)
          fatal2("unable to create empty state for processor", ld->name);
        close(fd);
        if ((fd =open_read("state")) == -1)
          fatal2("unable to open state for processor", ld->name);
      }
      else
        fatal2("unable to open state for processor", ld->name);
    }
    if (fd_move(4, fd) == -1)
      fatal2("unable to move filedescriptor for processor", ld->name);
    if ((fd =open_trunc("newstate")) == -1)
      fatal2("unable to open newstate for processor", ld->name);
    if (fd_move(5, fd) == -1)
      fatal2("unable to move filedescriptor for processor", ld->name);

    prog[0] = "sh";
    prog[1] = "-c";
    prog[2] = ld->processor.s;
    prog[3] = 0;
    execve("/bin/sh", prog, environ);
    fatal2("unable to run processor", ld->name);
  }
  ld->ppid =pid;
  return(1);
}
unsigned int processorstop(struct logdir *ld) {
  char f[28];

  if (ld->ppid) {
    sig_unblock(sig_hangup);
    while (wait_pid(&wstat, ld->ppid) == -1)
      pause2("error waiting for processor", ld->name);
    sig_block(sig_hangup);
    ld->ppid =0;
  }
  if (ld->fddir == -1) return(1);
  while (fchdir(ld->fddir) == -1)
    pause2("unable to change directory, want processor", ld->name);
  if (wait_exitcode(wstat) != 0) {
    warnx("processor failed, restart", ld->name);
    ld->fnsave[26] ='t';
    unlink(ld->fnsave);
    ld->fnsave[26] ='u';
    processorstart(ld);
    while (fchdir(fdwdir) == -1)
      pause1("unable to change to initial working directory");
    return(ld->processor.len ? 0 : 1);
  }
  ld->fnsave[26] ='t';
  byte_copy(f, 26, ld->fnsave);
  f[26] ='s'; f[27] =0;
  while (rename(ld->fnsave, f) == -1)
    pause2("unable to rename processed", ld->name);
  while (chmod(f, 0744) == -1)
    pause2("unable to set mode of processed", ld->name);
  ld->fnsave[26] ='u';
  if (unlink(ld->fnsave) == -1)
    strerr_warn5(WARNING, "unable to unlink: ", ld->name, "/", ld->fnsave, 0);
  while (rename("newstate", "state") == -1)
    pause2("unable to rename state", ld->name);
  if (verbose) strerr_warn5(INFO, "processed: ", ld->name, "/", f, 0);
  while (fchdir(fdwdir) == -1)
    pause1("unable to change to initial working directory");
  return(1);
}

void rmoldest(struct logdir *ld) {
  DIR *d;
  direntry *f;
  char oldest[FMT_PTIME];
  int n =0;

  oldest[0] ='A'; oldest[1] =oldest[27] =0;
  while (! (d =opendir(".")))
    pause2("unable to open directory, want rotate", ld->name);
  errno =0;
  while ((f =readdir(d)))
    if ((f->d_name[0] == '@') && (str_len(f->d_name) == 27)) {
      if (f->d_name[26] == 't') {
        if (unlink(f->d_name) == -1)
          warn2("unable to unlink processor leftover", f->d_name);
      }
      else {
        ++n;
        if (str_diff(f->d_name, oldest) < 0) byte_copy(oldest, 27, f->d_name);
      }
      errno =0;
    }
  if (errno) warn2("unable to read directory", ld->name);
  closedir(d);

  if (ld->nmax && (n > ld->nmax)) {
    if (verbose) strerr_warn5(INFO, "delete: ", ld->name, "/", oldest, 0);
    if ((*oldest == '@') && (unlink(oldest) == -1))
      warn2("unable to unlink oldest logfile", ld->name);
  }
}

unsigned int rotate(struct logdir *ld) {
  char tmp[FMT_ULONG +1];

  if (ld->fddir == -1) { ld->tmax =0; return(0); }
  if (ld->ppid) while(! processorstop(ld));

  while (fchdir(ld->fddir) == -1)
    pause2("unable to change directory, want rotate", ld->name);

  /* create new filename */
  ld->fnsave[25] ='.';
  if (ld->processor.len)
    ld->fnsave[26] ='u';
  else
    ld->fnsave[26] ='s';
  ld->fnsave[27] =0;
  do {
    taia_now(&now);
    fmt_taia(ld->fnsave, &now);
    errno =0;
  } while ((stat(ld->fnsave, &st) != -1) || (errno != error_noent));

  if (ld->tmax && taia_less(&ld->trotate, &now)) {
    taia_uint(&ld->trotate, ld->tmax);
    taia_add(&ld->trotate, &now, &ld->trotate);
    if (taia_less(&ld->trotate, &trotate)) trotate =ld->trotate;
  }

  if (ld->size > 0) {
    buffer_flush(&ld->b);
    while (fsync(ld->fdcur) == -1)
      pause2("unable to fsync current logfile", ld->name);
    while (fchmod(ld->fdcur, 0744) == -1)
      pause2("unable to set mode of current", ld->name);
    close(ld->fdcur);
    if (verbose) {
      tmp[0] =' '; tmp[fmt_ulong(tmp +1, ld->size) +1] =0;
      strerr_warn6(INFO, "rename: ", ld->name, "/current ",
                   ld->fnsave, tmp, 0);
    }
    while (rename("current", ld->fnsave) == -1)
      pause2("unable to rename current", ld->name);
    while ((ld->fdcur =open_append("current")) == -1)
      pause2("unable to create new current", ld->name);
    coe(ld->fdcur);
    ld->size =0;
    while (fchmod(ld->fdcur, 0644) == -1)
      pause2("unable to set mode of current", ld->name);
    rmoldest(ld);
    processorstart(ld);
  }

  while (fchdir(fdwdir) == -1)
    pause1("unable to change to initial working directory");
  return(1);
}

int buffer_pwrite(int n, char *s, unsigned int len) {
  int i;

  if ((dir +n)->sizemax) {
    if ((dir +n)->size >= (dir +n)->sizemax) rotate(dir +n);
    if (len > ((dir +n)->sizemax -(dir +n)->size))
      len =(dir +n)->sizemax -(dir +n)->size;
  }
  while ((i =write((dir +n)->fdcur, s, len)) == -1) {
    if ((errno == ENOSPC) && ((dir +n)->nmin < (dir +n)->nmax)) {
      DIR *d;
      direntry *f;
      char oldest[FMT_PTIME];
      int j =0;

      while (fchdir((dir +n)->fddir) == -1)
        pause2("unable to change directory, want remove old logfile",
               (dir +n)->name);
      oldest[0] ='A'; oldest[1] =oldest[27] =0;
      while (! (d =opendir(".")))
        pause2("unable to open directory, want remove old logfile",
               (dir +n)->name);
      errno =0;
      while ((f =readdir(d)))
        if ((f->d_name[0] == '@') && (str_len(f->d_name) == 27)) {
          ++j;
          if (str_diff(f->d_name, oldest) < 0)
            byte_copy(oldest, 27, f->d_name);
        }
      if (errno) warn2("unable to read directory, want remove old logfile",
                       (dir +n)->name);
      closedir(d);
      errno =ENOSPC;
      if (j > (dir +n)->nmin)
        if (*oldest == '@') {
          strerr_warn5(WARNING, "out of disk space, delete: ", (dir +n)->name,
                       "/", oldest, 0);
          errno =0;
          if (unlink(oldest) == -1) {
            warn2("unable to unlink oldest logfile", (dir +n)->name);
            errno =ENOSPC;
          }
          while (fchdir(fdwdir) == -1)
            pause1("unable to change to initial working directory");
        }
    }
    if (errno) pause2("unable to write to current", (dir +n)->name);
  }

  (dir +n)->size +=i;
  if ((dir +n)->sizemax)
    if (s[i -1] == '\n')
      if ((dir +n)->size >= ((dir +n)->sizemax -linemax)) rotate(dir +n);
  return(i);
}

void logdir_close(struct logdir *ld) {
  if (ld->fddir == -1) return;
  if (verbose) strerr_warn3(INFO, "close: ", ld->name, 0);
  close(ld->fddir);
  ld->fddir =-1;
  if (ld->fdcur == -1) return; /* impossible */
  buffer_flush(&ld->b);
  while (fsync(ld->fdcur) == -1)
    pause2("unable to fsync current logfile", ld->name);
  while (fchmod(ld->fdcur, 0744) == -1)
    pause2("unable to set mode of current", ld->name);
  close(ld->fdcur);
  ld->fdcur =-1;
  if (ld->fdlock == -1) return; /* impossible */
  close(ld->fdlock);
  ld->fdlock =-1;
  while (! stralloc_copys(&ld->processor, "")) pause_nomem();
}

/* taken from libdjbdns */
unsigned int ip4_scan(const char *s,char ip[4])
{
  unsigned int i;
  unsigned int len;
  unsigned long u;
 
  len = 0;
  i = scan_ulong(s,&u); if (!i) return 0; ip[0] = u; s += i; len += i;
  if (*s != '.') return 0; ++s; ++len;
  i = scan_ulong(s,&u); if (!i) return 0; ip[1] = u; s += i; len += i;
  if (*s != '.') return 0; ++s; ++len;
  i = scan_ulong(s,&u); if (!i) return 0; ip[2] = u; s += i; len += i;
  if (*s != '.') return 0; ++s; ++len;
  i = scan_ulong(s,&u); if (!i) return 0; ip[3] = u; s += i; len += i;
  return len;
}

unsigned int logdir_open(struct logdir *ld, const char *fn) {
  int i;

  if ((ld->fddir =open_read(fn)) == -1) {
    warn2("unable to open log directory", (char*)fn);
    return(0);
  }
  coe(ld->fddir);
  if (fchdir(ld->fddir) == -1) {
    logdir_close(ld);
    warn2("unable to change directory", (char*)fn);
    return(0);
  }
  ld->fdlock =open_append("lock");
  if ((ld->fdlock == -1) || (lock_exnb(ld->fdlock) == -1)) {
    logdir_close(ld);
    warn2("unable to lock directory", (char*)fn);
    while (fchdir(fdwdir) == -1)
      pause1("unable to change to initial working directory");
    return(0);
  }
  coe(ld->fdlock);

  ld->size =0;
  ld->sizemax =1000000;
  ld->nmax =ld->nmin =10;
  ld->tmax =0;
  ld->name =(char*)fn;
  ld->ppid =0;
  ld->match ='+';
  ld->udpaddr.sin_port =0;
  ld->udponly =0;
  while (! stralloc_copys(&ld->prefix, "")) pause_nomem();
  while (! stralloc_copys(&ld->inst, "")) pause_nomem();
  while (! stralloc_copys(&ld->processor, "")) pause_nomem();

  /* read config */
  if ((i =openreadclose("config", &sa, 128)) == -1)
    warn2("unable to read config", ld->name);
  if (i != 0) {
    int len, c;
    unsigned long port;

    if (verbose) strerr_warn4(INFO, "read: ", ld->name, "/config", 0);
    for (i =0; i +1 < sa.len; ++i) {
      len =byte_chr(&sa.s[i], sa.len -i, '\n');
      sa.s[len +i] =0;
      switch(sa.s[i]) {
      case '\n':
      case '#':
         break;
      case '+':
      case '-':
      case 'e':
      case 'E':
        while (! stralloc_catb(&ld->inst, &sa.s[i], len)) pause_nomem();
        while (! stralloc_0(&ld->inst)) pause_nomem();
        break;
      case 's':
        switch (sa.s[scan_ulong(&sa.s[i +1], &ld->sizemax) +i +1]) {
        case 'm': ld->sizemax *=1024;
        case 'k': ld->sizemax *=1024;
        }
        break;
      case 'n':
        scan_ulong(&sa.s[i +1], &ld->nmax);
        break;
      case 'N':
        scan_ulong(&sa.s[i +1], &ld->nmin);
        break;
      case 't':
        switch (sa.s[scan_ulong(&sa.s[i +1], &ld->tmax) +i +1]) {
        /* case 'd': ld->tmax *=24; */
        case 'h': ld->tmax *=60;
        case 'm': ld->tmax *=60;
        }
        if (ld->tmax) {
          taia_uint(&ld->trotate, ld->tmax);
          taia_add(&ld->trotate, &now, &ld->trotate);
          if (! tmaxflag || taia_less(&ld->trotate, &trotate))
            trotate =ld->trotate;
          tmaxflag =1;
        }
        break;
      case '!':
        if (len > 1) {
          while (! stralloc_copys(&ld->processor, &sa.s[i +1])) pause_nomem();
          while (! stralloc_0(&ld->processor)) pause_nomem();
        }
        break;
      case 'U':
        ld->udponly =1;
      case 'u':
        if (! (c =ip4_scan(sa.s +i +1, (char *)&ld->udpaddr.sin_addr))) {
          warnx("unable to scan ip address", sa.s +i +1);
          break;
        }
        if (sa.s[i +1 +c] == ':') {
          scan_ulong(sa.s +i +c +2, &port);
          if (port == 0) {
            warnx("unable to scan port number", sa.s +i +c +2);
            break;
          }
        }
        else
          port =514;
        ld->udpaddr.sin_port =htons(port);
        break;
      case 'p':
        if (len > 1) {
          while (! stralloc_copys(&ld->prefix, &sa.s[i +1])) pause_nomem();
          while (! stralloc_0(&ld->prefix)) pause_nomem();
        }
        break;
      }
      i +=len;
    }
  }

  /* open current */
  if ((i =stat("current", &st)) != -1) {
    if (st.st_size && ! (st.st_mode & S_IXUSR)) {
      ld->fnsave[25] ='.'; ld->fnsave[26] ='u'; ld->fnsave[27] =0;
      do {
        taia_now(&now);
        fmt_taia(ld->fnsave, &now);
        errno =0;
      } while ((stat(ld->fnsave, &st) != -1) || (errno != error_noent));
      while (rename("current", ld->fnsave) == -1)
        pause2("unable to rename current", ld->name);
      rmoldest(ld);
      i =-1;
    }
    else
      ld->size =st.st_size;
  }
  else
    if (errno != error_noent) {
      logdir_close(ld);
      warn2("unable to stat current", ld->name);
      while (fchdir(fdwdir) == -1)
        pause1("unable to change to initial working directory");
      return(0);
    }
  while ((ld->fdcur =open_append("current")) == -1)
    pause2("unable to open current", ld->name);
  coe(ld->fdcur);
  while (fchmod(ld->fdcur, 0644) == -1)
    pause2("unable to set mode of current", ld->name);
  buffer_init(&ld->b, buffer_pwrite, ld -dir, ld->btmp, buflen);
  
  if (verbose) {
    if (i == 0) strerr_warn4(INFO, "append: ", ld->name, "/current", 0);
    else strerr_warn4(INFO, "new: ", ld->name, "/current", 0);
  }
  
  while (fchdir(fdwdir) == -1)
    pause1("unable to change to initial working directory");
  return(1);
}

void logdirs_reopen(void) {
  int l;
  int ok =0;

  tmaxflag =0;
  taia_now(&now);
  for (l =0; l < dirn; ++l) {
    logdir_close(&dir[l]);    
    if (logdir_open(&dir[l], fndir[l])) ok =1;
  }
  if (! ok) fatalx("no functional log directories.");
}

int buffer_pread(int fd, char *s, unsigned int len) {
  int i;

  for (i =0; i < dirn; ++i) buffer_flush(&dir[i].b);
  if (rotateasap) {
    for (i =0; i < dirn; ++i) rotate(dir +i);
    rotateasap =0;
  }
  if (exitasap) {
    if (linecomplete) return(0);
    len =1;
  }
  if (reopenasap) {
    logdirs_reopen();
    reopenasap =0;
  }
  taia_now(&now);
  taia_uint(&trotate, 2744);
  taia_add(&trotate, &now, &trotate);
  for (i =0; i < dirn; ++i)
    if ((dir +i)->tmax) {
      if (taia_less(&dir[i].trotate, &now)) rotate(dir +i);
      if (taia_less(&dir[i].trotate, &trotate)) trotate =dir[i].trotate;
    }
  sig_unblock(sig_term);
  sig_unblock(sig_child);
  sig_unblock(sig_alarm);
  sig_unblock(sig_hangup);
  iopause(&in, 1, &trotate, &now);
  sig_block(sig_term);
  sig_block(sig_child);
  sig_block(sig_alarm);
  sig_block(sig_hangup);
  i =read(fd, s, len);
  if (i == -1) {
    if (errno == error_again) errno =error_intr;
    if (errno != error_intr) warn("unable to read standard input");
  }
  if (i > 0) linecomplete =(s[i -1] == '\n');
  return(i);
}
void sig_term_handler(void) {
  if (verbose) strerr_warn2(INFO, "sigterm received.", 0);
  exitasap =1;
}
void sig_child_handler(void) {
  int pid, l;

  if (verbose) strerr_warn2(INFO, "sigchild received.", 0);
  while ((pid =wait_nohang(&wstat)) > 0)
    for (l =0; l < dirn; ++l)
      if (dir[l].ppid == pid) {
        dir[l].ppid =0;
        processorstop(&dir[l]);
        break;
      }
}
void sig_alarm_handler(void) {
  if (verbose) strerr_warn2(INFO, "sigalarm received.", 0);
  rotateasap =1;
}
void sig_hangup_handler(void) {
  if (verbose) strerr_warn2(INFO, "sighangup received.", 0);
  reopenasap =1;
}

void logmatch(struct logdir *ld) {
  int i;

  ld->match ='+';
  ld->matcherr ='E';
  for (i =0; i < ld->inst.len; ++i) {
    switch(ld->inst.s[i]) {
    case '+':
    case '-':
      if (pmatch(&ld->inst.s[i +1], line, linelen))
        ld->match =ld->inst.s[i];
      break;
    case 'e':
    case 'E':
      if (pmatch(&ld->inst.s[i +1], line, linelen))
        ld->matcherr =ld->inst.s[i];
      break;
    }
    i +=byte_chr(&ld->inst.s[i], ld->inst.len -i, 0);
  }
}
int main(int argc, const char **argv) {
  int i;
  int opt;

  progname =*argv;

  while ((opt =getopt(argc, argv, "R:r:l:b:tvV")) != opteof) {
    switch(opt) {
    case 'R':
      replace =optarg;
      if (! repl) repl ='_';
      break;
    case 'r':
      repl =*optarg;
      if (! repl || *(optarg +1)) usage();
      break;
    case 'l':
      scan_ulong(optarg, &linemax);
      if (linemax == 0) linemax =1000;
      break;
    case 'b':
      scan_ulong(optarg, &buflen);
      if (buflen == 0) buflen =1024;
      break;
    case 't':
      if (++timestamp > 3) timestamp =3;
      break;
    case 'v':
      ++verbose;
      break;
    case 'V': strerr_warn1(VERSION, 0);
    case '?': usage();
    }
  }
  argv +=optind;

  dirn =argc -optind;
  if (dirn <= 0) usage();
  if (buflen <= linemax) usage();
  if ((fdwdir =open_read(".")) == -1)
    fatal("unable to open current working directory");
  coe(fdwdir);
  dir =(struct logdir*)alloc(dirn *sizeof(struct logdir));
  if (! dir) die_nomem();
  for (i =0; i < dirn; ++i) {
    dir[i].fddir =-1; dir[i].fdcur =-1;
    dir[i].btmp =(char*)alloc(buflen *sizeof(char));
    if (! dir[i].btmp) die_nomem();
    dir[i].ppid =0;
  }
  databuf =(char*)alloc(buflen *sizeof(char));
  if (! databuf) die_nomem();
  buffer_init(&data, buffer_pread, 0, databuf, buflen);
  line =(char*)alloc(linemax *sizeof(char));
  if (! line) die_nomem();
  fndir =argv;
  in.fd =0;
  in.events =IOPAUSE_READ;
  ndelay_on(in.fd);

  sig_block(sig_term);
  sig_block(sig_child);
  sig_block(sig_alarm);
  sig_block(sig_hangup);
  sig_catch(sig_term, sig_term_handler);
  sig_catch(sig_child, sig_child_handler);
  sig_catch(sig_alarm, sig_alarm_handler);
  sig_catch(sig_hangup, sig_hangup_handler);

  logdirs_reopen();

  for(;;) {
    char ch;

    linelen =0;
    for (linelen =0; linelen < linemax; ++linelen) {
      if (buffer_GETC(&data, &ch) <= 0) {
        exitasap =1;
        break;
      }
      if (! linelen && timestamp) {
        taia_now(&now);
        switch (timestamp) {
        case 1: fmt_taia(stamp, &now); break;
        case 2: fmt_ptime(stamp, &now); break;
        case 3: fmt_ptime_iso8601(stamp, &now); break;
        }
        stamp[25] =' '; stamp[26] =0;
      }
      if (ch == '\n') break;
      if (repl) {
        if ((ch < 32) || (ch > 126))
          ch =repl;
        else
          for (i =0; replace[i]; ++i)
            if (ch == replace[i]) {
              ch =repl;
              break;
            }
      }
      line[linelen] =ch;
    }
    if (exitasap && ! data.p) break; /* data buffer is empty */
    for (i =0; i < dirn; ++i)
      if (dir[i].fddir != -1) {
        if (dir[i].inst.len) logmatch(&dir[i]);
        if (dir[i].matcherr == 'e') {
          if (timestamp) buffer_puts(buffer_2, stamp);
          if (dir[i].prefix.len) buffer_puts(buffer_2, dir[i].prefix.s);
          buffer_put(buffer_2, line, linelen);
          if (linelen == linemax) buffer_puts(buffer_2, "...");
          buffer_put(buffer_2, "\n", 1); buffer_flush(buffer_2);
        }
        if (dir[i].match != '+') continue;
        if (dir[i].udpaddr.sin_port != 0) {
          fdudp =socket(AF_INET, SOCK_DGRAM, 0);
          if (fdudp)
            if (ndelay_on(fdudp) == -1) {
              close(fdudp);
              fdudp =-1;
            }
          if (fdudp == -1) {
            buffer_puts(&dir[i].b, "warning: no udp socket available: ");
            if (timestamp) buffer_puts(&dir[i].b, stamp);
            if (dir[i].prefix.len) buffer_puts(&dir[i].b, dir[i].prefix.s);
            buffer_put(&dir[i].b, line, linelen);
            buffer_put(&dir[i].b, "\n", 1);
            buffer_flush(&dir[i].b);
          }
          else {
            while (! stralloc_copys(&sa, "")) pause_nomem();
            if (timestamp)
              while (! stralloc_cats(&sa, stamp)) pause_nomem();
            if (dir[i].prefix.len)
              while (! stralloc_cats(&sa, dir[i].prefix.s)) pause_nomem();
            while (! stralloc_catb(&sa, line, linelen)) pause_nomem();
            if (linelen == linemax)
              while (! stralloc_cats(&sa, "...")) pause_nomem();
            while (! stralloc_append(&sa, "\n")) pause_nomem();
            if (sendto(fdudp, sa.s, sa.len, 0,
                       (struct sockaddr *)&dir[i].udpaddr,
                       sizeof(dir[i].udpaddr)) != sa.len) {
              buffer_puts(&dir[i].b, "warning: failure sending through udp: ");
              buffer_put(&dir[i].b, sa.s, sa.len);
              buffer_flush(&dir[i].b);
            }
            close(fdudp);
          }
        }
        if (! dir[i].udponly) {
          if (timestamp) buffer_puts(&dir[i].b, stamp);
          if (dir[i].prefix.len) buffer_puts(&dir[i].b, dir[i].prefix.s);
          buffer_put(&dir[i].b, line, linelen);
        }
      }
    if (linelen == linemax)
      for (;;) {
        if (buffer_GETC(&data, &ch) <= 0) {
          exitasap =1;
          break;
        }
        if (ch == '\n') break;
        for (i =0; i < dirn; ++i)
          if (dir[i].fddir != -1) {
            if (dir[i].match != '+') continue;
            if (! dir[i].udponly) buffer_PUTC(&dir[i].b, ch);
          }
      }
    for (i =0; i < dirn; ++i)
      if (dir[i].fddir != -1) {
        if (dir[i].match != '+') continue;
        if (! dir[i].udponly) {
          ch ='\n';
          buffer_PUTC(&dir[i].b, ch);
          buffer_flush(&dir[i].b);
        }
      }
  }
  
  for (i =0; i < dirn; ++i) {
    if (dir[i].ppid) while (! processorstop(&dir[i]));
    logdir_close(&dir[i]);
  }
  _exit(0);
}
