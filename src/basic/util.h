/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <alloca.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <locale.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "formats-util.h"
#include "macro.h"
#include "missing.h"
#include "time-util.h"

size_t page_size(void) _pure_;
#define PAGE_ALIGN(l) ALIGN_TO((l), page_size())

static inline const char* yes_no(bool b) {
        return b ? "yes" : "no";
}

static inline const char* true_false(bool b) {
        return b ? "true" : "false";
}

static inline const char* one_zero(bool b) {
        return b ? "1" : "0";
}

void execute_directories(const char* const* directories, usec_t timeout, char *argv[]);

bool plymouth_running(void);

bool display_is_local(const char *display) _pure_;
int socket_from_display(const char *display, char **path);

int block_get_whole_disk(dev_t d, dev_t *ret);

#define NULSTR_FOREACH(i, l)                                    \
        for ((i) = (l); (i) && *(i); (i) = strchr((i), 0)+1)

#define NULSTR_FOREACH_PAIR(i, j, l)                             \
        for ((i) = (l), (j) = strchr((i), 0)+1; (i) && *(i); (i) = strchr((j), 0)+1, (j) = *(i) ? strchr((i), 0)+1 : (i))

extern int saved_argc;
extern char **saved_argv;

bool kexec_loaded(void);

int prot_from_flags(int flags) _const_;

int fork_agent(pid_t *pid, const int except[], unsigned n_except, const char *path, ...);

bool in_initrd(void);

void *xbsearch_r(const void *key, const void *base, size_t nmemb, size_t size,
                 int (*compar) (const void *, const void *, void *),
                 void *arg);

/**
 * Normal qsort requires base to be nonnull. Here were require
 * that only if nmemb > 0.
 */
static inline void qsort_safe(void *base, size_t nmemb, size_t size, comparison_fn_t compar) {
        if (nmemb <= 1)
                return;

        assert(base);
        qsort(base, nmemb, size, compar);
}

int on_ac_power(void);

#define memzero(x,l) (memset((x), 0, (l)))
#define zero(x) (memzero(&(x), sizeof(x)))

static inline void *mempset(void *s, int c, size_t n) {
        memset(s, c, n);
        return (uint8_t*)s + n;
}

static inline void _reset_errno_(int *saved_errno) {
        errno = *saved_errno;
}

#define PROTECT_ERRNO _cleanup_(_reset_errno_) __attribute__((unused)) int _saved_errno_ = errno

static inline int negative_errno(void) {
        /* This helper should be used to shut up gcc if you know 'errno' is
         * negative. Instead of "return -errno;", use "return negative_errno();"
         * It will suppress bogus gcc warnings in case it assumes 'errno' might
         * be 0 and thus the caller's error-handling might not be triggered. */
        assert_return(errno > 0, -EINVAL);
        return -errno;
}

static inline unsigned u64log2(uint64_t n) {
#if __SIZEOF_LONG_LONG__ == 8
        return (n > 1) ? (unsigned) __builtin_clzll(n) ^ 63U : 0;
#else
#error "Wut?"
#endif
}

static inline unsigned u32ctz(uint32_t n) {
#if __SIZEOF_INT__ == 4
        return __builtin_ctz(n);
#else
#error "Wut?"
#endif
}

static inline unsigned log2i(int x) {
        assert(x > 0);

        return __SIZEOF_INT__ * 8 - __builtin_clz(x) - 1;
}

static inline unsigned log2u(unsigned x) {
        assert(x > 0);

        return sizeof(unsigned) * 8 - __builtin_clz(x) - 1;
}

static inline unsigned log2u_round_up(unsigned x) {
        assert(x > 0);

        if (x == 1)
                return 0;

        return log2u(x - 1) + 1;
}

bool id128_is_valid(const char *s) _pure_;

int container_get_leader(const char *machine, pid_t *pid);

int namespace_open(pid_t pid, int *pidns_fd, int *mntns_fd, int *netns_fd, int *userns_fd, int *root_fd);
int namespace_enter(int pidns_fd, int mntns_fd, int netns_fd, int userns_fd, int root_fd);

uint64_t physical_memory(void);

int update_reboot_param_file(const char *param);

int version(void);
