/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>

#include "sd-readahead.h"

#if (__GNUC__ >= 4)
#  ifdef SD_EXPORT_SYMBOLS
/* Export symbols */
#    define _sd_export_ __attribute__ ((visibility("default")))
#  else
/* Don't export the symbols */
#    define _sd_export_ __attribute__ ((visibility("hidden")))
#  endif
#else
#  define _sd_export_
#endif

static int touch(const char *path) {

#if !defined(DISABLE_SYSTEMD) && defined(__linux__)
        int fd;

        mkdir("/run/systemd", 0755);
        mkdir("/run/systemd/readahead", 0755);

        fd = open(path, O_WRONLY|O_CREAT|O_CLOEXEC|O_NOCTTY, 0666);
        if (fd < 0)
                return -errno;

        for (;;) {
                if (close(fd) >= 0)
                        break;

                if (errno != EINTR)
                        return -errno;
        }

#endif
        return 0;
}

_sd_export_ int sd_readahead(const char *action) {

        if (!action)
                return -EINVAL;

        if (strcmp(action, "cancel") == 0)
                return touch("/run/systemd/readahead/cancel");
        else if (strcmp(action, "done") == 0)
                return touch("/run/systemd/readahead/done");
        else if (strcmp(action, "noreplay") == 0)
                return touch("/run/systemd/readahead/noreplay");

        return -EINVAL;
}
