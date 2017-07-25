#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include "strerr.h"
#include "error.h"
#include "taia.h"
#include "sig.h"
#include "env.h"
#include "coe.h"
#include "ndelay.h"
#include "fifo.h"
#include "open.h"
#include "lock.h"
#include "iopause.h"
#include "wait.h"
#include "fd.h"
#include "buffer.h"
#include "fmt.h"
#include "byte.h"

#define USAGE " dir"

#define VERSION "$Id: ecf467746d7b97ff0fddb88b9d44cca201c74160 $"

char *progname;
int selfpipe[2];

/* state */
#define S_DOWN 0
#define S_RUN 1
#define S_FINISH 2
/* ctrl */
#define C_NOOP 0
#define C_TERM 1
#define C_PAUSE 2
/* want */
#define W_UP 0
#define W_DOWN 1
#define W_EXIT 2

struct svdir {
  int pid;
  int state;
  int ctrl;
  int want;
  struct taia start;
  int wstat;
  int fdlock;
  int fdcontrol;
  int fdcontrolwrite;
  int islog;
};
struct svdir svd[2];

int sigterm =0;
int haslog =0;
int pidchanged =1;
int logpipe[2];
char *dir;

void usage () { strerr_die4x(1, "usage: ", progname, USAGE, "\n"); }

void fatal(char *m) {
  strerr_die5sys(111, "runsv ", dir, ": fatal: ", m, ": ");
}
void fatal2(char *m1, char *m2) {
  strerr_die6sys(111, "runsv ", dir, ": fatal: ", m1, m2, ": ");
}
void fatalx(char *m1, char *m2) {
  strerr_die5x(111, "runsv ", dir, ": fatal: ", m1, m2);
}
void warn(char *m) {
  strerr_warn5("runsv ", dir, ": warning: ", m, ": ", &strerr_sys);
}
void warn2(char *m1, char *m2) {
  strerr_warn6("runsv ", dir, ": warning: ", m1, m2, ": ", &strerr_sys);
}
void warnx(char *m1, char *m2, char *m3) {
  strerr_warn6("runsv ", dir, ": warning: ", m1, m2, m3, 0);
}

void stopservice(struct svdir *);

void s_child() { write(selfpipe[1], "", 1); }
void s_term() {
  sigterm =1;
  write(selfpipe[1], "", 1); /* XXX */
}

void update_status(struct svdir *s) {
  unsigned long l;
  int fd;
  char status[20];
  char bspace[64];
  buffer b;
  char spid[FMT_ULONG];
  char *fstatus ="supervise/status";
  char *fstatusnew ="supervise/status.new";
  char *fstat ="supervise/stat";
  char *fstatnew ="supervise/stat.new";
  char *fpid ="supervise/pid";
  char *fpidnew ="supervise/pid.new";

  if (s->islog) {
    fstatus ="log/supervise/status";
    fstatusnew ="log/supervise/status.new";
    fstat ="log/supervise/stat";
    fstatnew ="log/supervise/stat.new";
    fpid ="log/supervise/pid";
    fpidnew ="log/supervise/pid.new";
  }

  /* pid */
  if (pidchanged) {
    if ((fd =open_trunc(fpidnew)) == -1) {
      warn2("unable to open ", fpidnew);
      return;
    }
    buffer_init(&b, buffer_unixwrite, fd, bspace, sizeof bspace);
    spid[fmt_ulong(spid, (unsigned long)s->pid)] =0;
    if (s->pid) {
      buffer_puts(&b, spid);
      buffer_puts(&b, "\n");
      buffer_flush(&b);
    }
    close(fd);
    if (rename(fpidnew, fpid) == -1) {
      warn2("unable to rename pid.new to ", fpid);
      return;
    }
    pidchanged =0;
  }

  /* stat */
  if ((fd =open_trunc(fstatnew)) == -1) {
    warn2("unable to open ", fstatnew);
    return;
  }
  buffer_init(&b, buffer_unixwrite, fd, bspace, sizeof bspace);
  switch (s->state) {
  case S_DOWN:
    buffer_puts(&b, "down");
    break;
  case S_RUN:
    buffer_puts(&b, "run");
    break;
  case S_FINISH:
    buffer_puts(&b, "finish");
    break;
  }
  if (s->ctrl & C_PAUSE) buffer_puts(&b, ", paused");
  if (s->ctrl & C_TERM) buffer_puts(&b, ", got TERM");
  if (s->state != S_DOWN)
    switch(s->want) {
    case W_DOWN:
      buffer_puts(&b, ", want down");
      break;
    case W_EXIT:
      buffer_puts(&b, ", want exit");
      break;
    }
  buffer_puts(&b, "\n");
  buffer_flush(&b);
  close(fd);
  if (rename(fstatnew, fstat) == -1)
    warn2("unable to rename stat.new to ", fstat);

  /* supervise compatibility */
  taia_pack(status, &s->start);
  l =(unsigned long)s->pid;
  status[12] =l; l >>=8;
  status[13] =l; l >>=8;
  status[14] =l; l >>=8;
  status[15] =l;
  if (s->ctrl & C_PAUSE)
    status[16] =1;
  else
    status[16] =0;
  if (s->want == W_UP)
    status[17] ='u';
  else
    status[17] ='d';
  if (s->ctrl & C_TERM)
    status[18] =1;
  else
    status[18] =0;
  status[19] =s->state;
  if ((fd =open_trunc(fstatusnew)) == -1) {
    warn2("unable to open ", fstatusnew);
    return;
  }
  if ((l =write(fd, status, sizeof status)) == -1) {
    warn2("unable to write ", fstatusnew);
    close(fd);
    unlink(fstatusnew);
    return;
  }
  close(fd);
  if (l < sizeof status) {
    warnx("unable to write ", fstatusnew, ": partial write.");
    return;
  }
  if (rename(fstatusnew, fstatus) == -1)
    warn2("unable to rename status.new to ", fstatus);
}
unsigned int custom(struct svdir *s, char c) {
  int pid;
  int w;
  char a[10];
  struct stat st;
  char *prog[2];

  if (s->islog) return(0);
  byte_copy(a, 10, "control/?");
  a[8] =c;
  if (stat(a, &st) == 0) {
    if (st.st_mode & S_IXUSR) {
      if ((pid =fork()) == -1) {
        warn2("unable to fork for ", a);
        return(0);
      }
      if (! pid) {
        if (haslog && fd_copy(1, logpipe[1]) == -1)
          warn2("unable to setup stdout for ", a);
        prog[0] =a;
        prog[1] =0;
        execve(a, prog, environ);
        fatal("unable to run control/?");
      }
      while (wait_pid(&w, pid) == -1) {
        if (errno == error_intr) continue;
        warn2("unable to wait for child ", a);
        return(0);
      }
      return(! wait_exitcode(w));
    }
  }
  else {
    if (errno == error_noent) return(0);
    warn2("unable to stat ", a);
  }
  return(0);
}
void stopservice(struct svdir *s) {
  if (s->pid && ! custom(s, 't')) {
    kill(s->pid, SIGTERM);
    s->ctrl |=C_TERM;
    update_status(s);
  }
  if (s->want == W_DOWN) {
    kill(s->pid, SIGCONT);
    custom(s, 'd'); return;
  }
  if (s->want == W_EXIT) {
    kill(s->pid, SIGCONT);
    custom(s, 'x');
  }
}

void startservice(struct svdir *s) {
  int p;
  char *run[4];
  char code[FMT_ULONG];
  char stat[FMT_ULONG];

  if (s->state == S_FINISH) {
    run[0] ="./finish";
    code[fmt_ulong(code, wait_exitcode(s->wstat))] =0;
    run[1] =wait_crashed(s->wstat) ? "-1" : code;
    stat[fmt_ulong(stat, s->wstat & 0xff)] =0;
    run[2] =stat;
    run[3] =0;
  }
  else {
    run[0] ="./run";
    custom(s, 'u');
    run[1] =0;
  }

  if (s->pid != 0) stopservice(s); /* should never happen */
  while ((p =fork()) == -1) {
    warn("unable to fork, sleeping");
    sleep(5);
  }
  if (p == 0) {
    /* child */
    if (haslog) {
      if (s->islog) {
        if (fd_copy(0, logpipe[0]) == -1)
          fatal("unable to setup filedescriptor for ./log/run");
        close(logpipe[1]);
        if (chdir("./log") == -1)
          fatal("unable to change directory to ./log");        
      }
      else {
        if (fd_copy(1, logpipe[1]) == -1)
          fatal("unable to setup filedescriptor for ./run");
        close(logpipe[0]);
      }
    }
    sig_uncatch(sig_child);
    sig_unblock(sig_child);
    sig_uncatch(sig_term);
    sig_unblock(sig_term);
    execve(*run, run, environ);
    if (s->islog)
      fatal2("unable to start log/", *run);
    else
      fatal2("unable to start ", *run);
  }
  if (s->state != S_FINISH) {
    taia_now(&s->start);
    s->state =S_RUN;
  }
  s->pid =p;
  pidchanged =1;
  s->ctrl =C_NOOP;
  update_status(s);
}
int ctrl(struct svdir *s, char c) {
  switch(c) {
  case 'd': /* down */
    s->want =W_DOWN;
    update_status(s);
    if (s->state == S_RUN) stopservice(s);
    break;
  case 'u': /* up */
    s->want =W_UP;
    update_status(s);
    if (s->state == S_DOWN) startservice(s);
    break;
  case 'x': /* exit */
    if (s->islog) break;
    s->want =W_EXIT;
    update_status(s);
    if (s->state == S_RUN) stopservice(s);
    break;
  case 't': /* sig term */
    if (s->state == S_RUN) stopservice(s);
    break;
  case 'k': /* sig kill */
    if ((s->state == S_RUN) && ! custom(s, c)) kill(s->pid, SIGKILL);
    s->state =S_DOWN;
    break;
  case 'p': /* sig pause */
    if ((s->state == S_RUN) && ! custom(s, c)) kill(s->pid, SIGSTOP);
    s->ctrl |=C_PAUSE;
    update_status(s);
    break;
  case 'c': /* sig cont */
    if ((s->state == S_RUN) && ! custom(s, c)) kill(s->pid, SIGCONT);
    if (s->ctrl & C_PAUSE) s->ctrl &=~C_PAUSE;
    update_status(s);
    break;
  case 'o': /* once */
    s->want =W_DOWN;
    update_status(s);
    if (s->state == S_DOWN) startservice(s);
    break;
  case 'a': /* sig alarm */
    if ((s->state == S_RUN) && ! custom(s, c)) kill(s->pid, SIGALRM);
    break;
  case 'h': /* sig hup */
    if ((s->state == S_RUN) && ! custom(s, c)) kill(s->pid, SIGHUP);
    break;
  case 'i': /* sig int */
    if ((s->state == S_RUN) && ! custom(s, c)) kill(s->pid, SIGINT);
    break;
  case 'q': /* sig quit */
    if ((s->state == S_RUN) && ! custom(s, c)) kill(s->pid, SIGQUIT);
    break;
  case '1': /* sig usr1 */
    if ((s->state == S_RUN) && ! custom(s, c)) kill(s->pid, SIGUSR1);
    break;
  case '2': /* sig usr2 */
    if ((s->state == S_RUN) && ! custom(s, c)) kill(s->pid, SIGUSR2);
    break;
  }
  return(1);
}

int main(int argc, char **argv) {
  struct stat s;
  int fd;
  int r;
  char buf[256];

  progname =argv[0];
  if (! argv[1] || argv[2]) usage();
  dir =argv[1];

  if (pipe(selfpipe) == -1) fatal("unable to create selfpipe");
  coe(selfpipe[0]);
  coe(selfpipe[1]);
  ndelay_on(selfpipe[0]);
  ndelay_on(selfpipe[1]);
  
  sig_block(sig_child);
  sig_catch(sig_child, s_child);
  sig_block(sig_term);
  sig_catch(sig_term, s_term);

  if (chdir(dir) == -1) fatal("unable to change to directory");
  svd[0].pid =0;
  svd[0].state =S_DOWN;
  svd[0].ctrl =C_NOOP;
  svd[0].want =W_UP;
  svd[0].islog =0;
  svd[1].pid =0;
  taia_now(&svd[0].start);
  if (stat("down", &s) != -1) svd[0].want =W_DOWN;

  if (stat("log", &s) == -1) {
    if (errno != error_noent)
      warn("unable to stat() ./log: ");
  }
  else {
    if (! S_ISDIR(s.st_mode))
      warnx("./log", 0, ": not a directory.");
    else {
      haslog =1;
      svd[1].state =S_DOWN;
      svd[1].ctrl =C_NOOP;
      svd[1].want =W_UP;
      svd[1].islog =1;
      taia_now(&svd[1].start);
      if (stat("log/down", &s) != -1)
        svd[1].want =W_DOWN;
      if (pipe(logpipe) == -1)
        fatal("unable to create log pipe");
      coe(logpipe[0]);
      coe(logpipe[1]);
    }
  }

  if (mkdir("supervise", 0700) == -1) {
    if ((r =readlink("supervise", buf, 256)) != -1) {
      if (r == 256)
        fatalx("unable to readlink ./supervise: ", "name too long");
      buf[r] =0;
      mkdir(buf, 0700);
    }
    else {
      if ((errno != ENOENT) && (errno != EINVAL))
        fatal("unable to readlink ./supervise");
    }
  }
  if ((svd[0].fdlock =open_append("supervise/lock")) == -1)
    fatal("unable to open supervise/lock");
  if (lock_exnb(svd[0].fdlock) == -1) fatal("unable to lock supervise/lock");
  coe(svd[0].fdlock);
  if (haslog) {
    if (mkdir("log/supervise", 0700) == -1) {
      if ((r =readlink("log/supervise", buf, 256)) != -1) {
        if (r == 256)
          fatalx("unable to readlink ./log/supervise: ", "name too long");
        buf[r] =0;
        if ((fd =open_read(".")) == -1)
          fatal("unable to open current directory");
        if (chdir("./log") == -1)
          fatal("unable to change directory to ./log"); 
        mkdir(buf, 0700);
        if (fchdir(fd) == -1)
          fatal("unable to change back to service directory");
        close(fd);
      }
      else {
        if ((errno != ENOENT) && (errno != EINVAL))
          fatal("unable to readlink ./log/supervise");
      }
    }
    if ((svd[1].fdlock =open_append("log/supervise/lock")) == -1)
      fatal("unable to open log/supervise/lock");
    if (lock_ex(svd[1].fdlock) == -1)
      fatal("unable to lock log/supervise/lock");
    coe(svd[1].fdlock);
  }

  fifo_make("supervise/control", 0600);
  if (stat("supervise/control", &s) == -1)
    fatal("unable to stat supervise/control");
  if (!S_ISFIFO(s.st_mode))
    fatalx("supervise/control exists but is not a fifo", "");
  if ((svd[0].fdcontrol =open_read("supervise/control")) == -1)
    fatal("unable to open supervise/control");
  coe(svd[0].fdcontrol);
  if ((svd[0].fdcontrolwrite =open_write("supervise/control")) == -1)
    fatal("unable to open supervise/control");
  coe(svd[0].fdcontrolwrite);
  update_status(&svd[0]);
  if (haslog) {
    fifo_make("log/supervise/control", 0600);
    if (stat("supervise/control", &s) == -1)
      fatal("unable to stat log/supervise/control");
    if (!S_ISFIFO(s.st_mode))
      fatalx("log/supervise/control exists but is not a fifo", "");
    if ((svd[1].fdcontrol =open_read("log/supervise/control")) == -1)
      fatal("unable to open log/supervise/control");
    coe(svd[1].fdcontrol);
    if ((svd[1].fdcontrolwrite =open_write("log/supervise/control")) == -1)
      fatal("unable to open log/supervise/control");
    coe(svd[1].fdcontrolwrite);
    update_status(&svd[1]);
  }
  fifo_make("supervise/ok",0600);
  if ((fd =open_read("supervise/ok")) == -1)
    fatal("unable to read supervise/ok");
  coe(fd);
  if (haslog) {
    fifo_make("log/supervise/ok",0600);
    if ((fd =open_read("log/supervise/ok")) == -1)
      fatal("unable to read log/supervise/ok");
    coe(fd);
  }
  for (;;) {
    iopause_fd x[3];
    struct taia deadline;
    struct taia now;
    char ch;

    if (haslog)
      if (! svd[1].pid && (svd[1].want == W_UP)) startservice(&svd[1]);
    if (! svd[0].pid)
      if ((svd[0].want == W_UP) || (svd[0].state == S_FINISH))
        startservice(&svd[0]);

    x[0].fd =selfpipe[0];
    x[0].events =IOPAUSE_READ;
    x[1].fd =svd[0].fdcontrol;
    x[1].events =IOPAUSE_READ;
    if (haslog) {
      x[2].fd =svd[1].fdcontrol;
      x[2].events =IOPAUSE_READ;
    }
    taia_now(&now);
    taia_uint(&deadline, 3600);
    taia_add(&deadline, &now, &deadline);

    sig_unblock(sig_term);
    sig_unblock(sig_child);
    iopause(x, 2 +haslog, &deadline, &now);
    sig_block(sig_term);
    sig_block(sig_child);

    while (read(selfpipe[0], &ch, 1) == 1)
      ;
    for (;;) {
      int child;
      int wstat;
      
      child =wait_nohang(&wstat);
      if (!child) break;
      if ((child == -1) && (errno != error_intr)) break;
      if (child == svd[0].pid) {
        svd[0].pid =0;
        pidchanged =1;
        svd[0].wstat =wstat;
        svd[0].ctrl &=~C_TERM;
        if (svd[0].state != S_FINISH)
          if ((fd =open_read("finish")) != -1) {
            close(fd);
            svd[0].state =S_FINISH;
            update_status(&svd[0]);
            continue;
          }
        svd[0].state =S_DOWN;
        taia_uint(&deadline, 1);
        taia_add(&deadline, &svd[0].start, &deadline);
        taia_now(&svd[0].start);
        update_status(&svd[0]);
        if (taia_less(&svd[0].start, &deadline)) sleep(1);
      }
      if (haslog) {
        if (child == svd[1].pid) {
          svd[1].pid =0;
          pidchanged =1;
          svd[1].state =S_DOWN;
          svd[1].ctrl &=~C_TERM;
          taia_uint(&deadline, 1);
          taia_add(&deadline, &svd[1].start, &deadline);
          taia_now(&svd[1].start);
          update_status(&svd[1]);
          if (taia_less(&svd[1].start, &deadline)) sleep(1);
        }
      }
    }
    if (read(svd[0].fdcontrol, &ch, 1) == 1) ctrl(&svd[0], ch);
    if (haslog)
      if (read(svd[1].fdcontrol, &ch, 1) == 1) ctrl(&svd[1], ch);

    if (sigterm) { ctrl(&svd[0], 'x'); sigterm =0; }

    if ((svd[0].want == W_EXIT) && (svd[0].state == S_DOWN)) {
      if (svd[1].pid == 0) _exit(0);
      if (svd[1].want != W_EXIT) {
        svd[1].want =W_EXIT;
        /* stopservice(&svd[1]); */
        update_status(&svd[1]);
        if (close(logpipe[1]) == -1) warn("unable to close logpipe[1]");
        if (close(logpipe[0]) == -1) warn("unable to close logpipe[0]");
      }
    }
  }
  _exit(0);
}
