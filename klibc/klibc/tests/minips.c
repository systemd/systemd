/*
 * Copyright 1998 by Albert Cahalan; all rights reserved.
 * This file may be used subject to the terms and conditions of the
 * GNU Library General Public License Version 2, or any later version
 * at your option, as published by the Free Software Foundation.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Library General Public License for more details.
 */

/* This is a minimal /bin/ps, designed to be smaller than the old ps
 * while still supporting some of the more important features of the
 * new ps. (for total size, note that this ps does not need libproc)
 * It is suitable for Linux-on-a-floppy systems only.
 *
 * Maintainers: do not compile or install for normal systems.
 * Anyone needing this will want to tweak their compiler anyway.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

#include <asm/param.h>  /* HZ */
#include <asm/page.h>   /* PAGE_SIZE */

static int P_euid;
static int P_pid;
static char P_cmd[16];
static char P_state;
static int P_ppid, P_pgrp, P_session, P_tty, P_tpgid;
static unsigned long P_flags, P_min_flt, P_cmin_flt, P_maj_flt, P_cmaj_flt, P_utime, P_stime;
static long P_cutime, P_cstime, P_priority, P_nice, P_timeout, P_it_real_value;
static unsigned long P_start_time, P_vsize;
static long P_rss;
static unsigned long P_rss_rlim, P_start_code, P_end_code, P_start_stack, P_kstk_esp, P_kstk_eip;
static unsigned P_signal, P_blocked, P_sigignore, P_sigcatch;
static unsigned long P_wchan, P_nswap, P_cnswap;


#if 0
static int screen_cols = 80;
static int w_count;
#endif

static int want_one_pid;
static const char *want_one_command;
static int select_notty;
static int select_all;

static int ps_format;
static int old_h_option;

/* we only pretend to support this */
static int show_args;    /* implicit with -f and all BSD options */
static int bsd_c_option; /* this option overrides the above */

static int ps_argc;    /* global argc */
static char **ps_argv; /* global argv */
static int thisarg;    /* index into ps_argv */
static char *flagptr;  /* current location in ps_argv[thisarg] */


#ifndef PAGE_SIZE
#warning PAGE_SIZE not defined, assuming it is 4096
#define PAGE_SIZE 4096
#endif

#ifndef HZ
#warning HZ not defined, assuming it is 100
#define HZ 100
#endif



static void usage(void){
  fprintf(stderr,
    "-C   select by command name (minimal ps only accepts one)\n"
    "-p   select by process ID (minimal ps only accepts one)\n"
    "-e   all processes (same as ax)\n"
    "a    all processes w/ tty, including other users\n"
    "x    processes w/o controlling ttys\n"
    "-f   full format\n"
    "-j,j job control format\n"
    "v    virtual memory format\n"
    "-l,l long format\n"
    "u    user-oriented format\n"
    "-o   user-defined format (limited support, only \"ps -o pid=\")\n"
    "h    no header\n"
/*
    "-A   all processes (same as ax)\n"
    "c    true command name\n"
    "-w,w wide output\n"
*/
  );
  exit(1);
}

/*
 * Return the next argument, or call the usage function.
 * This handles both:   -oFOO   -o FOO
 */
static const char *get_opt_arg(void){
  const char *ret;
  ret = flagptr+1;    /* assume argument is part of ps_argv[thisarg] */
  if(*ret) return ret;
  if(++thisarg >= ps_argc) usage();   /* there is nothing left */
  /* argument is the new ps_argv[thisarg] */
  ret = ps_argv[thisarg];
  if(!ret || !*ret) usage();
  return ret;
}


/* return the PID, or 0 if nothing good */
static void parse_pid(const char *str){
  char *endp;
  int num;
  if(!str)            goto bad;
  num = strtol(str, &endp, 0);
  if(*endp != '\0')   goto bad;
  if(num<1)           goto bad;
  if(want_one_pid)    goto bad;
  want_one_pid = num;
  return;
bad:
  usage();
}

/***************** parse SysV options, including Unix98  *****************/
static void parse_sysv_option(void){
  do{
    switch(*flagptr){
    /**** selection ****/
    case 'C': /* end */
      if(want_one_command) usage();
      want_one_command = get_opt_arg();
      return; /* can't have any more options */
    case 'p': /* end */
      parse_pid(get_opt_arg());
      return; /* can't have any more options */
    case 'A':
    case 'e':
      select_all++;
      select_notty++;
case 'w':    /* here for now, since the real one is not used */
      break;
    /**** output format ****/
    case 'f':
      show_args = 1;
      /* FALL THROUGH */
    case 'j':
    case 'l':
      if(ps_format) usage();
      ps_format = *flagptr;
      break;
    case 'o': /* end */
      /* We only support a limited form: "ps -o pid="  (yes, just "pid=") */
      if(strcmp(get_opt_arg(),"pid=")) usage();
      if(ps_format) usage();
      ps_format = 'o';
      old_h_option++;
      return; /* can't have any more options */
    /**** other stuff ****/
#if 0
    case 'w':
      w_count++;
      break;
#endif
    default:
      usage();
    } /* switch */
  }while(*++flagptr);
}

/************************* parse BSD options **********************/
static void parse_bsd_option(void){
  do{
    switch(*flagptr){
    /**** selection ****/
    case 'a':
      select_all++;
      break;
    case 'x':
      select_notty++;
      break;
    case 'p': /* end */
      parse_pid(get_opt_arg());
      return; /* can't have any more options */
    /**** output format ****/
    case 'j':
    case 'l':
    case 'u':
    case 'v':
      if(ps_format) usage();
      ps_format = 0x80 | *flagptr;  /* use 0x80 to tell BSD from SysV */
      break;
    /**** other stuff ****/
    case 'c':
      bsd_c_option++;
#if 0
      break;
#endif
    case 'w':
#if 0
      w_count++;
#endif
      break;
    case 'h':
      old_h_option++;
      break;
    default:
      usage();
    } /* switch */
  }while(*++flagptr);
}

#if 0
/* not used yet */
static void choose_dimensions(void){
  struct winsize ws;
  char *columns;
  /* screen_cols is 80 by default */
  if(ioctl(1, TIOCGWINSZ, &ws) != -1 && ws.ws_col>30) screen_cols = ws.ws_col;
  columns = getenv("COLUMNS");
  if(columns && *columns){
    long t;
    char *endptr;
    t = strtol(columns, &endptr, 0);
    if(!*endptr && (t>30) && (t<(long)999999999)) screen_cols = (int)t;
  }
  if(w_count && (screen_cols<132)) screen_cols=132;
  if(w_count>1) screen_cols=999999999;
}
#endif

static void arg_parse(int argc, char *argv[]){
  int sel = 0;  /* to verify option sanity */
  ps_argc = argc;
  ps_argv = argv;
  thisarg = 0;
  /**** iterate over the args ****/
  while(++thisarg < ps_argc){
    flagptr = ps_argv[thisarg];
    switch(*flagptr){
    case '0' ... '9':
      show_args = 1;
      parse_pid(flagptr);
      break;
    case '-':
      flagptr++;
      parse_sysv_option();
      break;
    default:
      show_args = 1;
      parse_bsd_option();
      break;
    }
  }
  /**** sanity check and clean-up ****/
  if(want_one_pid) sel++;
  if(want_one_command) sel++;
  if(select_notty || select_all) sel++;
  if(sel>1 || select_notty>1 || select_all>1 || bsd_c_option>1 || old_h_option>1) usage();
  if(bsd_c_option) show_args = 0;
}

/* return 1 if it works, or 0 for failure */
static int stat2proc(int pid) {
    char buf[800]; /* about 40 fields, 64-bit decimal is about 20 chars */
    int num;
    int fd;
    char* tmp;
    struct stat sb; /* stat() used to get EUID */
    snprintf(buf, 32, "/proc/%d/stat", pid);
    if ( (fd = open(buf, O_RDONLY, 0) ) == -1 ) return 0;
    num = read(fd, buf, sizeof buf - 1);
    fstat(fd, &sb);
    P_euid = sb.st_uid;
    close(fd);
    if(num<80) return 0;
    buf[num] = '\0';
    tmp = strrchr(buf, ')');      /* split into "PID (cmd" and "<rest>" */
    *tmp = '\0';                  /* replace trailing ')' with NUL */
    /* parse these two strings separately, skipping the leading "(". */
    memset(P_cmd, 0, sizeof P_cmd);          /* clear */
    sscanf(buf, "%d (%15c", &P_pid, P_cmd);  /* comm[16] in kernel */
    num = sscanf(tmp + 2,                    /* skip space after ')' too */
       "%c "
       "%d %d %d %d %d "
       "%lu %lu %lu %lu %lu %lu %lu "
       "%ld %ld %ld %ld %ld %ld "
       "%lu %lu "
       "%ld "
       "%lu %lu %lu %lu %lu %lu "
       "%u %u %u %u " /* no use for RT signals */
       "%lu %lu %lu",
       &P_state,
       &P_ppid, &P_pgrp, &P_session, &P_tty, &P_tpgid,
       &P_flags, &P_min_flt, &P_cmin_flt, &P_maj_flt, &P_cmaj_flt, &P_utime, &P_stime,
       &P_cutime, &P_cstime, &P_priority, &P_nice, &P_timeout, &P_it_real_value,
       &P_start_time, &P_vsize,
       &P_rss,
       &P_rss_rlim, &P_start_code, &P_end_code, &P_start_stack, &P_kstk_esp, &P_kstk_eip,
       &P_signal, &P_blocked, &P_sigignore, &P_sigcatch,
       &P_wchan, &P_nswap, &P_cnswap
    );
/*    fprintf(stderr, "stat2proc converted %d fields.\n",num); */
    P_vsize /= 1024;
    P_rss *= (PAGE_SIZE/1024);
    if(num < 30) return 0;
    if(P_pid != pid) return 0;
    return 1;
}

static const char *do_time(unsigned long t){
  int hh,mm,ss;
  static char buf[32];
  int cnt = 0;
  t /= HZ;
  ss = t%60;
  t /= 60;
  mm = t%60;
  t /= 60;
  hh = t%24;
  t /= 24;
  if(t) cnt = snprintf(buf, sizeof buf, "%d-", (int)t);
  snprintf(cnt + buf, sizeof(buf)-cnt, "%02d:%02d:%02d", hh, mm, ss);
  return buf;
}

static void print_proc(void){
  char tty[16];
  snprintf(tty, sizeof tty, "%3d,%-3d", (P_tty>>8)&0xff, P_tty&0xff);
  switch(ps_format){
  case 0:
    printf("%5d %s %s", P_pid, tty, do_time(P_utime+P_stime));
    break;
  case 'o':
    printf("%d\n", P_pid);
    return; /* don't want the command */
  case 'l':
    printf(
      "%03x %c %5d %5d %5d  - %3d %3d - "
      "%5ld %06x %s %s",
      (unsigned)P_flags&0x777, P_state, P_euid, P_pid, P_ppid,
      (int)P_priority, (int)P_nice, P_vsize/(PAGE_SIZE/1024),
      (unsigned)(P_wchan&0xffffff), tty, do_time(P_utime+P_stime)
    );
    break;
  case 'f':
    printf(
      "%5d %5d %5d  -   -   %s %s",
      P_euid, P_pid, P_ppid, tty, do_time(P_utime+P_stime)
    );
    break;
  case 'j':
    printf(
      "%5d %5d %5d %s %s",
      P_pid, P_pgrp, P_session, tty, do_time(P_utime+P_stime)
    );
    break;
  case 'u'|0x80:
    printf(
      "%5d %5d    -    - %5ld %5ld %s %c   -   %s",
      P_euid, P_pid, P_vsize, P_rss, tty, P_state,
      do_time(P_utime+P_stime)
    );
    break;
  case 'v'|0x80:
    printf(
      "%5d %s %c %s %6d   -   - %5d    -",
      P_pid, tty, P_state, do_time(P_utime+P_stime), (int)P_maj_flt,
      (int)P_rss
    );
    break;
  case 'j'|0x80:
    printf(
      "%5d %5d %5d %5d %s %5d %c %5d %s",
      P_ppid, P_pid, P_pgrp, P_session, tty, P_tpgid, P_state, P_euid, do_time(P_utime+P_stime)
    );
    break;
  case 'l'|0x80:
    printf(
      "%03x %5d %5d %5d %3d %3d "
      "%5ld %4ld %06x %c %s %s",
      (unsigned)P_flags&0x777, P_euid, P_pid, P_ppid, (int)P_priority, (int)P_nice,
      P_vsize, P_rss, (unsigned)(P_wchan&0xffffff), P_state, tty, do_time(P_utime+P_stime)
    );
    break;
  default:
    break;
  }
  if(show_args) printf(" [%s]\n", P_cmd);
  else          printf(" %s\n", P_cmd);
}


int main(int argc, char *argv[]){
  arg_parse(argc, argv);
#if 0
  choose_dimensions();
#endif
  if(!old_h_option){
    const char *head;
    switch(ps_format){
    default: /* can't happen */
    case 0:        head = "  PID TTY         TIME CMD"; break;
    case 'l':      head = "  F S   UID   PID  PPID  C PRI  NI ADDR SZ WCHAN    TTY       TIME CMD"; break;
    case 'f':      head = "  UID   PID  PPID  C STIME   TTY       TIME CMD"; break;
    case 'j':      head = "  PID  PGID   SID TTY         TIME CMD"; break;
    case 'u'|0x80: head = "  UID   PID %CPU %MEM   VSZ   RSS   TTY   S START     TIME COMMAND"; break;
    case 'v'|0x80: head = "  PID   TTY   S     TIME  MAJFL TRS DRS   RSS %MEM COMMAND"; break;
    case 'j'|0x80: head = " PPID   PID  PGID   SID   TTY   TPGID S   UID     TIME COMMAND"; break;
    case 'l'|0x80: head = "  F   UID   PID  PPID PRI  NI   VSZ  RSS WCHAN  S   TTY       TIME COMMAND"; break;
    }
    printf("%s\n",head);
  }
  if(want_one_pid){
    if(stat2proc(want_one_pid)) print_proc();
    else exit(1);
  }else{
    struct dirent *ent;          /* dirent handle */
    DIR *dir;
    int ouruid;
    int found_a_proc;
    found_a_proc = 0;
    ouruid = getuid();
    dir = opendir("/proc");
    while(( ent = readdir(dir) )){
      if(*ent->d_name<'0' || *ent->d_name>'9') continue;
      if(!stat2proc(atoi(ent->d_name))) continue;
      if(want_one_command){
        if(strcmp(want_one_command,P_cmd)) continue;
      }else{
        if(!select_notty && P_tty==-1) continue;
        if(!select_all && P_euid!=ouruid) continue;
      }
      found_a_proc++;
      print_proc();
    }
    closedir(dir);
    exit(!found_a_proc);
  }
  return 0;
}
