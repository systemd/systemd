/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef foosddaemonhfoo
#define foosddaemonhfoo

/***
  Copyright 2010 Lennart Poettering

  Permission is hereby granted, free of charge, to any person
  obtaining a copy of this software and associated documentation files
  (the "Software"), to deal in the Software without restriction,
  including without limitation the rights to use, copy, modify, merge,
  publish, distribute, sublicense, and/or sell copies of the Software,
  and to permit persons to whom the Software is furnished to do so,
  subject to the following conditions:

  The above copyright notice and this permission notice shall be
  included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
  BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
  ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
  CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
***/

/* Reference implementation of a few systemd related interfaces for
 * writing daemons. These interfaces are trivial to implement, however
 * to simplify porting we provide this reference
 * implementation. Applications are free to reimplement the algorithms
 * described here. */

/*
  Log levels for usage on stderr:

          fprintf(stderr, SD_NOTICE "Hello World!");

  This is similar to printk() usage in the kernel.
*/

#define SD_EMERG   "<0>"  /* system is unusable */
#define SD_ALERT   "<1>"  /* action must be taken immediately */
#define SD_CRIT    "<2>"  /* critical conditions */
#define SD_ERR     "<3>"  /* error conditions */
#define SD_WARNING "<4>"  /* warning conditions */
#define SD_NOTICE  "<5>"  /* normal but significant condition */
#define SD_INFO    "<6>"  /* informational */
#define SD_DEBUG   "<7>"  /* debug-level messages */

/* The first passed file descriptor is fd 3 */
#define SD_LISTEN_FDS_START 3

/* Returns how many file descriptors have been passed, or a negative
 * errno code on failure. Optionally removes the $LISTEN_FDS and
 * $LISTEN_PID file descriptors from the environment (recommended). */
int sd_listen_fds(int unset_environment);

#endif
