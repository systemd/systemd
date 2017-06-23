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

#include <stdio.h>
#include <string.h>

#include "log.h"
#include "loopback-setup.h"

int main(int argc, char* argv[]) {
        int r;

        log_open();
        log_set_max_level(LOG_DEBUG);
        log_parse_environment();

        r = loopback_setup();
        if (r < 0)
                log_error_errno(r, "loopback: %m");

        return r >= 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
