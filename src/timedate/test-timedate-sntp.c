/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Kay Sievers

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

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/timex.h>
#include <sys/socket.h>

#include "sd-event.h"
#include "util.h"
#include "log.h"
#include "timedate-sntp.h"

typedef struct Manager Manager;
struct Manager {
        sd_event *event;
        SNTPContext *sntp;
};

static void manager_free(Manager *m);
DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_free);
#define _cleanup_manager_free_ _cleanup_(manager_freep)

static int manager_new(Manager **ret) {
        _cleanup_manager_free_ Manager *m = NULL;
        int r;

        m = new0(Manager, 1);
        if (!m)
                return -ENOMEM;

        r = sd_event_default(&m->event);
        if (r < 0)
                return r;

        *ret = m;
        m = NULL;

        return 0;
}

static void manager_free(Manager *m) {

        if (!m)
                return;

        m->sntp = sntp_unref(m->sntp);
        sd_event_unref(m->event);
        free(m);
}

static void manager_report(usec_t poll_usec, double offset, double delay, double jitter, bool spike) {
        log_info("%4llu %+10f %10f %10f%s",
                 poll_usec / USEC_PER_SEC, offset, delay, jitter, spike ? " spike" : "");
}

int main(int argc, char *argv[]) {
        _cleanup_manager_free_ Manager *m = NULL;
        const char *server;
        int r;

        r = manager_new(&m);
        if (r < 0)
                goto out;

        r = sntp_new(&m->sntp, m->event);
        if (r < 0)
                goto out;

        if (argv[1])
                log_set_max_level(LOG_DEBUG);
        else
                sntp_report_register(m->sntp, manager_report);

        //server = "216.239.32.15";       /* time1.google.com */
        //server = "192.53.103.108";      /* ntp1.ptb.de */
        server = "27.54.95.11";         /* au.pool.ntp.org */
        r = sntp_server_connect(m->sntp, server);

        if (r < 0)
                goto out;

        r = sd_event_loop(m->event);
        if (r < 0)
                goto out;

out:
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
