/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Michael Biebl

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
#include <stdlib.h>

#include "log.h"
#include "unit-name.h"

int main(int argc, char *argv[]) {
        char *escaped_name = NULL;

        if (argc != 2) {
                log_error("This program requires on argument.");
                return EXIT_FAILURE;
        }

        escaped_name = unit_name_escape(argv[1]);

        if (!escaped_name) {
                log_error("Failed to escape name.");
                return EXIT_FAILURE;
        }

        printf("%s", escaped_name);

        return EXIT_SUCCESS;
}
