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

#include <sys/socket.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/signalfd.h>
#include <getopt.h>
#include <stddef.h>

#include "log.h"
#include "macro.h"
#include "util.h"

static int send_on_socket(int fd, const char *socket_name, const void *packet, size_t size) {
        union {
                struct sockaddr sa;
                struct sockaddr_un un;
        } sa = {
                .un.sun_family = AF_UNIX,
        };

        assert(fd >= 0);
        assert(socket_name);
        assert(packet);

        strncpy(sa.un.sun_path, socket_name, sizeof(sa.un.sun_path));

        if (sendto(fd, packet, size, MSG_NOSIGNAL, &sa.sa, offsetof(struct sockaddr_un, sun_path) + strlen(socket_name)) < 0) {
                log_error("Failed to send: %m");
                return -1;
        }

        return 0;
}

int main(int argc, char *argv[]) {
        int fd = -1, r = EXIT_FAILURE;
        char packet[LINE_MAX];
        size_t length;

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        if (argc != 3) {
                log_error("Wrong number of arguments.");
                goto finish;
        }

        if (streq(argv[1], "1")) {

                packet[0] = '+';
                if (!fgets(packet+1, sizeof(packet)-1, stdin)) {
                        log_error("Failed to read password: %m");
                        goto finish;
                }

                truncate_nl(packet+1);
                length = 1 + strlen(packet+1) + 1;
        } else if (streq(argv[1], "0")) {
                packet[0] = '-';
                length = 1;
        } else {
                log_error("Invalid first argument %s", argv[1]);
                goto finish;
        }

        fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (fd < 0) {
                log_error("socket() failed: %m");
                goto finish;
        }

        if (send_on_socket(fd, argv[2], packet, length) < 0)
                goto finish;

        r = EXIT_SUCCESS;

finish:
        safe_close(fd);

        return r;
}
