/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2005-2008 Lennart Poettering
  Copyright 2014 Daniel Buch

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

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <resolv.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include "sd-resolve.h"

#include "alloc-util.h"
#include "macro.h"
#include "resolve-util.h"
#include "socket-util.h"
#include "string-util.h"

static int getaddrinfo_handler(sd_resolve_query *q, int ret, const struct addrinfo *ai, void *userdata) {
        const struct addrinfo *i;

        assert_se(q);

        if (ret != 0) {
                log_error("getaddrinfo error: %s %i", gai_strerror(ret), ret);
                return 0;
        }

        for (i = ai; i; i = i->ai_next) {
                _cleanup_free_ char *addr = NULL;

                assert_se(sockaddr_pretty(i->ai_addr, i->ai_addrlen, false, true, &addr) == 0);
                puts(addr);
        }

        printf("canonical name: %s\n", strna(ai->ai_canonname));

        return 0;
}

static int getnameinfo_handler(sd_resolve_query *q, int ret, const char *host, const char *serv, void *userdata) {
        assert_se(q);

        if (ret != 0) {
                log_error("getnameinfo error: %s %i", gai_strerror(ret), ret);
                return 0;
        }

        printf("Host: %s -- Serv: %s\n", strna(host), strna(serv));
        return 0;
}

int main(int argc, char *argv[]) {
        _cleanup_resolve_query_unref_ sd_resolve_query *q1 = NULL, *q2 = NULL;
        _cleanup_resolve_unref_ sd_resolve *resolve = NULL;
        int r = 0;

        struct addrinfo hints = {
                .ai_family = PF_UNSPEC,
                .ai_socktype = SOCK_STREAM,
                .ai_flags = AI_CANONNAME
        };

        struct sockaddr_in sa = {
                .sin_family = AF_INET,
                .sin_port = htons(80)
        };

        assert_se(sd_resolve_default(&resolve) >= 0);

        /* Test a floating resolver query */
        sd_resolve_getaddrinfo(resolve, NULL, "redhat.com", "http", NULL, getaddrinfo_handler, NULL);

        /* Make a name -> address query */
        r = sd_resolve_getaddrinfo(resolve, &q1, argc >= 2 ? argv[1] : "www.heise.de", NULL, &hints, getaddrinfo_handler, NULL);
        if (r < 0)
                log_error_errno(r, "sd_resolve_getaddrinfo(): %m");

        /* Make an address -> name query */
        sa.sin_addr.s_addr = inet_addr(argc >= 3 ? argv[2] : "193.99.144.71");
        r = sd_resolve_getnameinfo(resolve, &q2, (struct sockaddr*) &sa, sizeof(sa), 0, SD_RESOLVE_GET_BOTH, getnameinfo_handler, NULL);
        if (r < 0)
                log_error_errno(r, "sd_resolve_getnameinfo(): %m");

        /* Wait until the two queries are completed */
        while (sd_resolve_query_is_done(q1) == 0 ||
               sd_resolve_query_is_done(q2) == 0) {

                r = sd_resolve_wait(resolve, (uint64_t) -1);
                if (r < 0) {
                        log_error_errno(r, "sd_resolve_wait(): %m");
                        assert_not_reached("sd_resolve_wait() failed");
                }
        }

        return 0;
}
