/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include <unistd.h>

#include "sd-daemon.h"

#include "strv.h"

int main(int argc, char*argv[]) {
        _cleanup_strv_free_ char **l = NULL;
        int n, i;

        n = sd_listen_fds_with_names(false, &l);
        if (n < 0) {
                log_error_errno(n, "Failed to get listening fds: %m");
                return EXIT_FAILURE;
        }

        for (i = 0; i < n; i++)
                log_info("fd=%i name=%s\n", SD_LISTEN_FDS_START + i, l[i]);

        sd_notify(0,
                  "STATUS=Starting up");
        sleep(5);

        sd_notify(0,
                  "STATUS=Running\n"
                  "READY=1");
        sleep(5);

        sd_notify(0,
                  "STATUS=Reloading\n"
                  "RELOADING=1");
        sleep(5);

        sd_notify(0,
                  "STATUS=Running\n"
                  "READY=1");
        sleep(5);

        sd_notify(0,
                  "STATUS=Quitting\n"
                  "STOPPING=1");
        sleep(5);

        return EXIT_SUCCESS;
}
