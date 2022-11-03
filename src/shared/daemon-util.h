/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "sd-daemon.h"

#include "macro.h"

#define NOTIFY_READY "READY=1\n" "STATUS=Processing requests..."
#define NOTIFY_STOPPING "STOPPING=1\n" "STATUS=Shutting down..."

static inline const char *notify_start(const char *start, const char *stop) {
        if (start)
                (void) sd_notify(false, start);

        return stop;
}

/* This is intended to be used with _cleanup_ attribute. */
static inline void notify_on_cleanup(const char **p) {
        if (*p)
                (void) sd_notify(false, *p);
}

int notify_remove_fd_warnf(const char *format, ...) _printf_(1, 2);
int close_and_notify_warn(int fd, const char *name);
int notify_push_fdf(int fd, const char *format, ...) _printf_(2, 3);
