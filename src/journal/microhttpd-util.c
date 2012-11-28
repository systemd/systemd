/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Zbigniew Jędrzejewski-Szmek

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

#include <stddef.h>
#include <stdio.h>

#include "microhttpd-util.h"
#include "log.h"
#include "macro.h"
#include "util.h"

void microhttpd_logger(void *arg, const char *fmt, va_list ap) {
        _cleanup_free_ char *f = NULL;

        if (asprintf(&f, "microhttpd: %s", fmt) <= 0) {
                log_oom();
                return;
        }

        DISABLE_WARNING_FORMAT_NONLITERAL;
        log_metav(LOG_INFO, NULL, 0, NULL, f, ap);
        REENABLE_WARNING;
}

#ifdef HAVE_GNUTLS

static int log_level_map[] = {
        LOG_DEBUG,
        LOG_WARNING, /* gnutls session audit */
        LOG_DEBUG,   /* gnutls debug log */
        LOG_WARNING, /* gnutls assert log */
        LOG_INFO,    /* gnutls handshake log */
        LOG_DEBUG,   /* gnutls record log */
        LOG_DEBUG,   /* gnutls dtls log */
        LOG_DEBUG,
        LOG_DEBUG,
        LOG_DEBUG,
        LOG_DEBUG,   /* gnutls hard log */
        LOG_DEBUG,   /* gnutls read log */
        LOG_DEBUG,   /* gnutls write log */
        LOG_DEBUG,   /* gnutls io log */
        LOG_DEBUG,   /* gnutls buffers log */
};

void log_func_gnutls(int level, const char *message) {
        int ourlevel;

        assert_se(message);

        if (0 <= level && level < (int) ELEMENTSOF(log_level_map))
                ourlevel = log_level_map[level];
        else
                level = LOG_DEBUG;

        log_meta(ourlevel, NULL, 0, NULL, "gnutls: %s", message);
}

#endif
