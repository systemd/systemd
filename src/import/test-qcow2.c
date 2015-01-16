/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2015 Lennart Poettering

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

#include "log.h"
#include "util.h"

#include "qcow2-util.h"

int main(int argc, char *argv[]) {
        _cleanup_close_ int sfd = -1, dfd = -1;
        int r;

        if (argc != 3) {
                log_error("Needs two arguments.");
                return EXIT_FAILURE;
        }

        sfd = open(argv[1], O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (sfd < 0) {
                log_error_errno(errno, "Can't open source file: %m");
                return EXIT_FAILURE;
        }

        dfd = open(argv[2], O_WRONLY|O_CREAT|O_CLOEXEC|O_NOCTTY, 0666);
        if (dfd < 0) {
                log_error_errno(errno, "Can't open destination file: %m");
                return EXIT_FAILURE;
        }

        r = qcow2_convert(sfd, dfd);
        if (r < 0) {
                log_error_errno(r, "Failed to unpack: %m");
                return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
}
