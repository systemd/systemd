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

#include <sys/ioctl.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/watchdog.h>

#include "watchdog.h"
#include "log.h"

static int watchdog_fd = -1;
static usec_t watchdog_timeout = (usec_t) -1;

static int update_timeout(void) {
        int r;

        if (watchdog_fd < 0)
                return 0;

        if (watchdog_timeout == (usec_t) -1)
                return 0;
        else if (watchdog_timeout == 0) {
                int flags;

                flags = WDIOS_DISABLECARD;
                r = ioctl(watchdog_fd, WDIOC_SETOPTIONS, &flags);
                if (r < 0) {
                        log_warning("Failed to disable hardware watchdog: %m");
                        return -errno;
                }
        } else {
                int sec, flags;
                char buf[FORMAT_TIMESPAN_MAX];

                sec = (int) ((watchdog_timeout + USEC_PER_SEC - 1) / USEC_PER_SEC);
                r = ioctl(watchdog_fd, WDIOC_SETTIMEOUT, &sec);
                if (r < 0) {
                        log_warning("Failed to set timeout to %is: %m", sec);
                        return -errno;
                }

                watchdog_timeout = (usec_t) sec * USEC_PER_SEC;
                log_info("Set hardware watchdog to %s.", format_timespan(buf, sizeof(buf), watchdog_timeout, 0));

                flags = WDIOS_ENABLECARD;
                r = ioctl(watchdog_fd, WDIOC_SETOPTIONS, &flags);
                if (r < 0) {
                        log_warning("Failed to enable hardware watchdog: %m");
                        return -errno;
                }

                r = ioctl(watchdog_fd, WDIOC_KEEPALIVE, 0);
                if (r < 0) {
                        log_warning("Failed to ping hardware watchdog: %m");
                        return -errno;
                }
        }

        return 0;
}

static int open_watchdog(void) {
        struct watchdog_info ident;

        if (watchdog_fd >= 0)
                return 0;

        watchdog_fd = open("/dev/watchdog", O_WRONLY|O_CLOEXEC);
        if (watchdog_fd < 0)
                return -errno;

        if (ioctl(watchdog_fd, WDIOC_GETSUPPORT, &ident) >= 0)
                log_info("Hardware watchdog '%s', version %x",
                         ident.identity,
                         ident.firmware_version);

        return update_timeout();
}

int watchdog_set_timeout(usec_t *usec) {
        int r;

        watchdog_timeout = *usec;

        /* If we didn't open the watchdog yet and didn't get any
         * explicit timeout value set, don't do anything */
        if (watchdog_fd < 0 && watchdog_timeout == (usec_t) -1)
                return 0;

        if (watchdog_fd < 0)
                r = open_watchdog();
        else
                r = update_timeout();

        *usec = watchdog_timeout;

        return r;
}

int watchdog_ping(void) {
        int r;

        if (watchdog_fd < 0) {
                r = open_watchdog();
                if (r < 0)
                        return r;
        }

        r = ioctl(watchdog_fd, WDIOC_KEEPALIVE, 0);
        if (r < 0) {
                log_warning("Failed to ping hardware watchdog: %m");
                return -errno;
        }

        return 0;
}

void watchdog_close(bool disarm) {
        int r;

        if (watchdog_fd < 0)
                return;

        if (disarm) {
                int flags;

                /* Explicitly disarm it */
                flags = WDIOS_DISABLECARD;
                r = ioctl(watchdog_fd, WDIOC_SETOPTIONS, &flags);
                if (r < 0)
                        log_warning("Failed to disable hardware watchdog: %m");

                /* To be sure, use magic close logic, too */
                for (;;) {
                        static const char v = 'V';

                        if (write(watchdog_fd, &v, 1) > 0)
                                break;

                        if (errno != EINTR) {
                                log_error("Failed to disarm watchdog timer: %m");
                                break;
                        }
                }
        }

        watchdog_fd = safe_close(watchdog_fd);
}
