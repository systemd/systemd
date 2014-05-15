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

#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <assert.h>
#include <signal.h>
#include <errno.h>

#include "socket-util.h"
#include "sd-resolve.h"
#include "resolve-util.h"
#include "macro.h"

static int getaddrinfo_handler(sd_resolve_query *q, int ret, const struct addrinfo *ai, void *userdata) {
        const struct addrinfo *i;

        assert(q);

        if (ret != 0) {
                log_error("getaddrinfo error: %s %i\n", gai_strerror(ret), ret);
                return 0;
        }

        for (i = ai; i; i = i->ai_next) {
                _cleanup_free_ char *addr = NULL;

                assert_se(sockaddr_pretty(i->ai_addr, i->ai_addrlen, false, &addr) == 0);
                puts(addr);
        }

        printf("canonical name: %s\n", strna(ai->ai_canonname));

        return 0;
}

static int getnameinfo_handler(sd_resolve_query *q, int ret, const char *host, const char *serv, void *userdata) {
        assert(q);

        if (ret != 0) {
                log_error("getnameinfo error: %s %i\n", gai_strerror(ret), ret);
                return 0;
        }

        printf("Host: %s -- Serv: %s\n", strna(host), strna(serv));
        return 0;
}

static int res_handler(sd_resolve_query *q, int ret, unsigned char *answer, void *userdata) {
        int qdcount, ancount, len;
        const unsigned char *pos = answer + sizeof(HEADER);
        unsigned char *end = answer + ret;
        HEADER *head = (HEADER *) answer;
        char name[256];
        assert(q);

        if (ret < 0) {
                log_error("res_query() error: %s %i\n", strerror(errno), errno);
                return 0;
        }

        if (ret == 0) {
                log_error("No reply for SRV lookup\n");
                return 0;
        }

        qdcount = ntohs(head->qdcount);
        ancount = ntohs(head->ancount);

        printf("%d answers for srv lookup:\n", ancount);

        /* Ignore the questions */
        while (qdcount-- > 0 && (len = dn_expand(answer, end, pos, name, 255)) >= 0) {
                assert(len >= 0);
                pos += len + QFIXEDSZ;
        }

        /* Parse the answers */
        while (ancount-- > 0 && (len = dn_expand(answer, end, pos, name, 255)) >= 0) {
                /* Ignore the initial string */
                uint16_t pref, weight, port;
                assert(len >= 0);
                pos += len;
                /* Ignore type, ttl, class and dlen */
                pos += 10;

                GETSHORT(pref, pos);
                GETSHORT(weight, pos);
                GETSHORT(port, pos);
                len = dn_expand(answer, end, pos, name, 255);
                printf("\tpreference: %2d weight: %2d port: %d host: %s\n",
                       pref, weight, port, name);

                pos += len;
        }

        return 0;
}

int main(int argc, char *argv[]) {
        _cleanup_resolve_query_unref_ sd_resolve_query *q1 = NULL, *q2 = NULL, *q3 = NULL;
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
                log_error("sd_resolve_getaddrinfo(): %s\n", strerror(-r));

        /* Make an address -> name query */
        sa.sin_addr.s_addr = inet_addr(argc >= 3 ? argv[2] : "193.99.144.71");
        r = sd_resolve_getnameinfo(resolve, &q2, (struct sockaddr*) &sa, sizeof(sa), 0, SD_RESOLVE_GET_BOTH, getnameinfo_handler, NULL);
        if (r < 0)
                log_error("sd_resolve_getnameinfo(): %s\n", strerror(-r));

        /* Make a res_query() call */
        r = sd_resolve_res_query(resolve, &q3, "_xmpp-client._tcp.gmail.com", C_IN, T_SRV, res_handler, NULL);
        if (r < 0)
                log_error("sd_resolve_res_query(): %s\n", strerror(-r));

        /* Wait until the three queries are completed */
        while (sd_resolve_query_is_done(q1) == 0 ||
               sd_resolve_query_is_done(q2) == 0 ||
               sd_resolve_query_is_done(q3) == 0) {

                r = sd_resolve_wait(resolve, (uint64_t) -1);
                if (r < 0) {
                        log_error("sd_resolve_wait(): %s\n", strerror(-r));
                        assert_not_reached("sd_resolve_wait() failed");
                }
        }

        return 0;
}
