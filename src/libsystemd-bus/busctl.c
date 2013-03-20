/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

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

#include "strv.h"
#include "util.h"
#include "log.h"

#include "sd-bus.h"
#include "bus-message.h"
#include "bus-internal.h"

int main(int argc, char *argv[]) {
        _cleanup_bus_unref_ sd_bus *bus = NULL;
        _cleanup_strv_free_ char **l = NULL;
        char **i;
        int r;
        size_t max_i = 0;

        r = sd_bus_open_user(&bus);
        if (r < 0) {
                log_error("Failed to connect to bus: %s", strerror(-r));
                goto fail;
        }

        r = sd_bus_list_names(bus, &l);
        if (r < 0) {
                log_error("Failed to list names: %s", strerror(-r));
                goto fail;
        }

        strv_sort(l);

        STRV_FOREACH(i, l)
                max_i = MAX(max_i, strlen(*i));

        printf("%-*s %*s %-*s %-*s CONNECTION\n",
               (int) max_i, "NAME", 10, "PID", 15, "PROCESS", 16, "USER");

        STRV_FOREACH(i, l) {
                _cleanup_free_ char *owner = NULL;
                pid_t pid;
                uid_t uid;

                /* if ((*i)[0] == ':') */
                /*         continue; */

                printf("%-*s", (int) max_i, *i);

                r = sd_bus_get_owner_pid(bus, *i, &pid);
                if (r >= 0) {
                        _cleanup_free_ char *comm = NULL;

                        printf(" %10lu", (unsigned long) pid);

                        get_process_comm(pid, &comm);
                        printf(" %-15s", strna(comm));
                } else
                        printf("          - -              ");

                r = sd_bus_get_owner_uid(bus, *i, &uid);
                if (r >= 0) {
                        _cleanup_free_ char *u = NULL;

                        u = uid_to_name(uid);
                        if (!u) {
                                log_oom();
                                goto fail;
                        }

                        if (strlen(u) > 16)
                                u[16] = 0;

                        printf(" %-16s", u);
                } else
                        printf(" -               ");

                r = sd_bus_get_owner(bus, *i, &owner);
                if (r >= 0)
                        printf(" %s\n", owner);
                else
                        printf(" -\n");
        }

        r = 0;

fail:
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
