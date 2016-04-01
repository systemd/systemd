/***
  This file is part of systemd.

  Copyright 2016 Vitaly Kuznetsov

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

#include "fileio.h"

static const char *auto_online_blocks = "/sys/devices/system/memory/auto_online_blocks";

int main(int argc, char *argv[]) {
        int r;

        if (argc != 2) {
                log_error("This program requires one argument.");
                return EXIT_FAILURE;
        }

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        r = write_string_file(auto_online_blocks, argv[1], 0);
        if (r < 0) {
                log_error_errno(r, "Failed to write to %s: %m", auto_online_blocks);
                return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
}
