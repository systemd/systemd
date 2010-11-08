/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <string.h>

#include "log.h"
#include "util.h"

int main(int argc, char *argv[]) {
        int r = EXIT_SUCCESS;

        if (argc < 3) {
                log_error("This program requires at least two arguments.");
                return EXIT_FAILURE;
        }

        log_set_target(LOG_TARGET_SYSLOG_OR_KMSG);
        log_parse_environment();
        log_open();

        if (streq(argv[1], "create")) {

        } else if (streq(argv[1], "format")) {


        } else if (streq(argv[1], "remove")) {

        } else {
                log_error("Unknown verb %s.", argv[1]);
                goto finish;
        }

finish:
        return r;
}
