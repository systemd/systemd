/*
 * atexit.h
 *
 * atexit()/on_exit() internal definitions
 */

#ifndef ATEXIT_H
#define ATEXIT_H

struct atexit {
  void (*fctn)(int, void *);
  void *arg;			/* on_exit() parameter */
  struct atexit *next;
};

#endif /* ATEXIT_H */

