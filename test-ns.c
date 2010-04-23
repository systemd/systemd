/*-*- Mode: C; c-basic-offset: 8 -*-*/

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

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>

#include "namespace.h"
#include "log.h"

int main(int argc, char *argv[]) {
        const char * const writable[] = {
                "/home",
                NULL
        };

        const char * const readable[] = {
                "/",
                "/usr",
                "/boot",
                NULL
        };

        const char * const inaccessible[] = {
                "/home/lennart/projects",
                NULL
        };

        int r;

        if ((r = setup_namespace((char**) writable, (char**) readable, (char**) inaccessible, true, MS_SHARED)) < 0) {
                log_error("Failed to setup namespace: %s", strerror(-r));
                return 1;
        }

        execl("/bin/sh", "/bin/sh", NULL);
        log_error("execl(): %m");

        return 1;
}
