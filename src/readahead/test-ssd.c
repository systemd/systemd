/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Zbigniew Jędrzejewski-Szmek

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

#include "readahead-common.h"

int main(int argc, char *argv[]) {
        int i;

        for (i = 1; i < argc; i++) {
                char *name = argv[i];
                int r;

                r = fs_on_ssd(name);
                if (r < 0) {
                        log_error("%s: %s", name, strerror(-r));
                        return EXIT_FAILURE;
                }

                log_info("%s: %s", name, r ? "SSD" : "---");
        }

        return EXIT_SUCCESS;
}
