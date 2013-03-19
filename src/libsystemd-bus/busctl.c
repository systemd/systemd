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

#include "sd-bus.h"

int main(int argc, char *argv[]) {
        _cleanup_bus_unref_ sd_bus *bus = NULL;
        _cleanup_strv_free_ char **l = NULL;
        char **i;
        int r;

        r = bus_open_system(&bus);
        if (r < 0) {
                log_error("Failed to connect to bus: %s", strerror(-r));
                goto fail;
        }

        r = sd_bus_list_names(bus, &l);
        if (r < 0) {
                log_error("Failed to list names: %s", strerror(-r));
                goto fail;
        }

        STRV_FOREACH(i, l) {
                _cleanup_free_ char *owner = NULL;
                pid_t pid = 0;
                uid_t uid;
                bool uid_valid;

                r = sd_bus_get_owner(bus, *i, &owner);
                if (r == -ENXIO)
                        continue;

                r = sd_get_owner_pid(bus, *i, &pid);
                if (r == -ENXIO)
                        continue;

                r = sd_get_owner_uid(bus, *i, &pid);
                if (r == -ENXIO)
                        continue;
                uid_valid = r >= 0;

                printf("%s (%s) %llu %llu\n", *i, owner, (unsigned long long) pid, (unsigned long long) uid);
        }

        r = 0;

fail:
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
