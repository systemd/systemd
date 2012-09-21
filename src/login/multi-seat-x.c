/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering

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

#include <string.h>
#include <unistd.h>

#include "util.h"
#include "mkdir.h"

int main(int argc, char *argv[]) {

        int i;
        const char *seat = NULL;
        char **new_argv;
        _cleanup_free_ char *path = NULL;
        int r;
        _cleanup_fclose_ FILE *f = NULL;

        /* This binary will go away as soon as X natively takes the
         * arguments in question as command line parameters, instead
         * of requiring them in the configuration file. */

        /* If this file is removed, don't forget to remove the code
         * that invokes this in gdm and other display managers. */

        for (i = 1; i < argc; i++)
                if (streq(argv[i], "-seat"))
                        seat = argv[i+1];

        if (isempty(seat) || streq(seat, "seat0")) {
                argv[0] = (char*) X_SERVER;
                execv(X_SERVER, argv);
                log_error("Failed to execute real X server: %m");
                goto fail;
        }

        r = mkdir_safe_label("/run/systemd/multi-session-x", 0755, 0, 0);
        if (r < 0) {
                log_error("Failed to create directory: %s", strerror(-r));
                goto fail;
        }

        path = strappend("/run/systemd/multi-session-x/", seat);
        if (!path) {
                log_oom();
                goto fail;
        }

        f = fopen(path, "we");
        if (!f) {
                log_error("Failed to write configuration file: %m");
                goto fail;
        }

        fprintf(f,
                "Section \"ServerFlags\"\n"
                "        Option \"AutoAddDevices\" \"True\"\n"
                "        Option \"AllowEmptyInput\" \"True\"\n"
                "        Option \"DontVTSwitch\" \"True\"\n"
                "EndSection\n"
                "Section \"InputClass\"\n"
                "        Identifier \"Force Input Devices to Seat\"\n"
                "        Option \"GrabDevice\" \"True\"\n"
                "EndSection\n");

        fflush(f);

        if (ferror(f)) {
                log_error("Failed to write configuration file: %m");
                goto fail;
        }

        fclose(f);
        f = NULL;

        new_argv = newa(char*, argc + 3 + 1);
        memcpy(new_argv, argv, sizeof(char*) * (argc + 2 + 1));

        new_argv[0] = (char*) X_SERVER;
        new_argv[argc+0] = (char*) "-config";
        new_argv[argc+1] = path;
        new_argv[argc+2] = (char*) "-sharevts";
        new_argv[argc+3] = NULL;

        execv(X_SERVER, new_argv);
        log_error("Failed to execute real X server: %m");

fail:
        return EXIT_FAILURE;
}
