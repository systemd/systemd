/*
 * siglist.h
 *
 * Construct the signal list
 */

#include <signal.h>
#include <unistd.h>

const char * const sys_siglist[NSIG] = {
#ifdef SIGABRT
  [SIGABRT] = "Aborted",
#endif
#ifdef SIGALRM
  [SIGALRM] = "Alarm clock",
#endif
#ifdef SIGBUS
  [SIGBUS] = "Bus error",
#endif
#ifdef SIGCHLD
  [SIGCHLD] = "Child exited",
#endif
#if defined(SIGCLD) && (SIGCHLD != SIGCLD)
  [SIGCLD] = "Child exited",
#endif
#ifdef SIGEMT
  [SIGEMT] = "Emulation trap",
#endif
#ifdef SIGFPE
  [SIGFPE] = "Floating point exception",
#endif
#ifdef SIGHUP
  [SIGHUP] = "Hangup",
#endif
#ifdef SIGILL
  [SIGILL] = "Illegal instruction",
#endif
  /* SIGINFO == SIGPWR */
#ifdef SIGINT
  [SIGINT] = "Interrupt",
#endif
#ifdef SIGIO
  [SIGIO] = "I/O possible",
#endif
#if defined(SIGIOT) && (SIGIOT != SIGABRT)
  [SIGIOT] = "I/O trap",
#endif
#ifdef SIGKILL
  [SIGKILL] = "Killed",
#endif
#if defined(SIGLOST) && (SIGLOST != SIGIO) && (SIGLOST != SIGPWR)
  [SIGLOST] = "Lock lost",
#endif
#ifdef SIGPIPE
  [SIGPIPE] = "Broken pipe",
#endif
#if defined(SIGPOLL) && (SIGPOLL != SIGIO)
  [SIGPOLL] = "Pollable event",
#endif
#ifdef SIGPROF
  [SIGPROF] = "Profiling timer expired",
#endif
#ifdef SIGPWR
  [SIGPWR] = "Power failure",
#endif
#ifdef SIGQUIT
  [SIGQUIT] = "Quit",
#endif
  /* SIGRESERVE == SIGUNUSED */
#ifdef SIGSEGV
  [SIGSEGV] = "Segment violation",
#endif
#ifdef SIGSTKFLT
  [SIGSTKFLT] = "Stack fault",
#endif
#ifdef SIGSTOP
  [SIGSTOP] = "Stopped (signal)",
#endif
#ifdef SIGSYS
  [SIGSYS] = "Bad system call",
#endif
#ifdef SIGTERM
  [SIGTERM] = "Terminated",
#endif
#ifdef SIGTSTP
  [SIGTSTP] = "Stopped",
#endif
#ifdef SIGTTIN
  [SIGTTIN] = "Stopped (tty input)",
#endif
#ifdef SIGTTOU
  [SIGTTOU] = "Stopped (tty output)",
#endif
#ifdef SIGURG
  [SIGURG] = "Urgent I/O condition",
#endif
#ifdef SIGUSR1
  [SIGUSR1] = "User signal 1",
#endif
#ifdef SIGUSR2
  [SIGUSR2] = "User signal 2",
#endif
#ifdef SIGVTALRM
  [SIGVTALRM] = "Virtual timer expired",
#endif
#ifdef SIGWINCH
  [SIGWINCH] = "Window size changed",
#endif
#ifdef SIGXCPU
  [SIGXCPU] = "CPU time limit exceeded",
#endif
#ifdef SIGXFSZ
  [SIGXFSZ] = "File size limit exceeded",
#endif
};
