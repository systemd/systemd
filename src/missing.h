/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef foomissinghfoo
#define foomissinghfoo

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

/* Missing glibc definitions to access certain kernel APIs */

#include <sys/resource.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/oom.h>

#ifdef HAVE_AUDIT
#include <libaudit.h>
#endif

#include "macro.h"

#ifndef RLIMIT_RTTIME
#define RLIMIT_RTTIME 15
#endif

#ifndef F_LINUX_SPECIFIC_BASE
#define F_LINUX_SPECIFIC_BASE 1024
#endif

#ifndef F_SETPIPE_SZ
#define F_SETPIPE_SZ (F_LINUX_SPECIFIC_BASE + 7)
#endif

#ifndef F_GETPIPE_SZ
#define F_GETPIPE_SZ (F_LINUX_SPECIFIC_BASE + 8)
#endif

#ifndef IP_FREEBIND
#define IP_FREEBIND 15
#endif

#ifndef OOM_SCORE_ADJ_MIN
#define OOM_SCORE_ADJ_MIN (-1000)
#endif

#ifndef OOM_SCORE_ADJ_MAX
#define OOM_SCORE_ADJ_MAX 1000
#endif

#ifndef AUDIT_SERVICE_START
#define AUDIT_SERVICE_START 1130 /* Service (daemon) start */
#endif

#ifndef AUDIT_SERVICE_STOP
#define AUDIT_SERVICE_STOP 1131 /* Service (daemon) stop */
#endif

static inline int pivot_root(const char *new_root, const char *put_old) {
        return syscall(SYS_pivot_root, new_root, put_old);
}

#ifdef __x86_64__
#ifndef __NR_fanotify_init
#define __NR_fanotify_init 300
#endif
#ifndef __NR_fanotify_mark
#define __NR_fanotify_mark 301
#endif
#else
#ifndef __NR_fanotify_init
#define __NR_fanotify_init 338
#endif
#ifndef __NR_fanotify_mark
#define __NR_fanotify_mark 339
#endif
#endif

static inline int fanotify_init(unsigned int flags, unsigned int event_f_flags) {
        return syscall(__NR_fanotify_init, flags, event_f_flags);
}

static inline int fanotify_mark(int fanotify_fd, unsigned int flags, uint64_t mask,
                                int dfd, const char *pathname) {
        return syscall(__NR_fanotify_mark, fanotify_fd, flags, mask, dfd, pathname);
}

#endif
