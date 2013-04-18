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
        _cleanup_free_ char *f;
        if (asprintf(&f, "microhttpd: %s", fmt) <= 0) {
                log_oom();
                return;
        }
        log_metav(LOG_INFO, NULL, 0, NULL, f, ap);
}
