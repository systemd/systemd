/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2012 Lennart Poettering

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


#include <errno.h>

#include "audit-fd.h"

#ifdef HAVE_AUDIT

#include <libaudit.h>
#include <stdbool.h>

#include "fd-util.h"
#include "log.h"
#include "util.h"

static bool initialized = false;
static int audit_fd;

int get_audit_fd(void) {

        if (!initialized) {
                audit_fd = audit_open();

                if (audit_fd < 0) {
                        if (errno != EAFNOSUPPORT && errno != EPROTONOSUPPORT)
                                log_error_errno(errno, "Failed to connect to audit log: %m");

                        audit_fd = errno ? -errno : -EINVAL;
                }

                initialized = true;
        }

        return audit_fd;
}

void close_audit_fd(void) {

        if (initialized && audit_fd >= 0)
                safe_close(audit_fd);

        initialized = true;
        audit_fd = -ECONNRESET;
}

#else

int get_audit_fd(void) {
        return -EAFNOSUPPORT;
}

void close_audit_fd(void) {
}

#endif
