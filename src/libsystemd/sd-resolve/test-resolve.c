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

int main(int argc, char *argv[]) {
        int r = 0;
        _cleanup_resolve_unref_ sd_resolve *resolve = NULL;
        _cleanup_resolve_addrinfo_free_ struct addrinfo *ai = NULL;
        _cleanup_free_ unsigned char *srv = NULL;
        _cleanup_free_ char *host = NULL, *serv = NULL;
        sd_resolve_query *q1 = NULL, *q2 = NULL, *q3 = NULL;

        struct addrinfo hints = {
                .ai_family = PF_UNSPEC,
                .ai_socktype = SOCK_STREAM,
                .ai_flags = AI_CANONNAME
        };

        struct sockaddr_in sa = {
                .sin_family = AF_INET,
                .sin_port = htons(80)
        };

        assert_se(sd_resolve_new(&resolve) >= 0);

        /* Make a name -> address query */
        r = sd_resolve_getaddrinfo(resolve, &q1, argc >= 2 ? argv[1] : "www.heise.de", NULL, &hints);
        if (r < 0)
                log_error("sd_resolve_getaddrinfo(): %s\n", strerror(-r));

        /* Make an address -> name query */
        sa.sin_addr.s_addr = inet_addr(argc >= 3 ? argv[2] : "193.99.144.71"),
        r = sd_resolve_getnameinfo(resolve, &q2, (struct sockaddr*) &sa, sizeof(sa), 0, true, true);
        if (r < 0)
                log_error("sd_resolve_getnameinfo(): %s\n", strerror(-r));

        /* Make a res_query() call */
        r = sd_resolve_res_query(resolve, &q3, "_xmpp-client._tcp.gmail.com", C_IN, T_SRV);
        if (r < 0)
                log_error("sd_resolve_res_query(): %s\n", strerror(-r));

        /* Wait until the three queries are completed */
        while (sd_resolve_is_done(q1) == 0 ||
               sd_resolve_is_done(q2) == 0 ||
               sd_resolve_is_done(q3) == 0) {

                r = sd_resolve_wait(resolve, (uint64_t) -1);
                if (r < 0) {
                        log_error("sd_resolve_wait(): %s\n", strerror(-r));
                        assert_not_reached("sd_resolve_wait() failed");
                }
        }

        /* Interpret the result of the name -> addr query */
        r = sd_resolve_getaddrinfo_done(q1, &ai);
        if (r != 0)
                log_error("error: %s %i\n", gai_strerror(r), r);
        else {
                struct addrinfo *i;

                for (i = ai; i; i = i->ai_next) {
                        _cleanup_free_ char *addr = NULL;

                        assert_se(sockaddr_pretty(i->ai_addr, i->ai_addrlen, false, &addr) == 0);

                        puts(addr);
                }

                printf("canonical name: %s\n", strna(ai->ai_canonname));
        }

        /* Interpret the result of the addr -> name query */
        r = sd_resolve_getnameinfo_done(q2, &host, &serv);
        if (r)
                log_error("error: %s %i\n", gai_strerror(r), r);
        else
                printf("Host: %s -- Serv: %s\n", host, serv);

        /* Interpret the result of the SRV lookup */
        r = sd_resolve_res_done(q3, &srv);
        if (r < 0)
                log_error("error: %s %i\n", strerror(-r), r);
        else if (r == 0)
                log_error("No reply for SRV lookup\n");
        else {
                int qdcount, ancount, len;
                const unsigned char *pos = srv + sizeof(HEADER);
                unsigned char *end = srv + r;
                HEADER *head = (HEADER *)srv;
                char name[256];

                qdcount = ntohs(head->qdcount);
                ancount = ntohs(head->ancount);

                printf("%d answers for srv lookup:\n", ancount);

                /* Ignore the questions */
                while (qdcount-- > 0 && (len = dn_expand(srv, end, pos, name, 255)) >= 0) {
                        assert(len >= 0);
                        pos += len + QFIXEDSZ;
                }

                /* Parse the answers */
                while (ancount-- > 0 && (len = dn_expand(srv, end, pos, name, 255)) >= 0) {
                        /* Ignore the initial string */
                        uint16_t pref, weight, port;
                        assert(len >= 0);
                        pos += len;
                        /* Ignore type, ttl, class and dlen */
                        pos += 10;

                        GETSHORT(pref, pos);
                        GETSHORT(weight, pos);
                        GETSHORT(port, pos);
                        len = dn_expand(srv, end, pos, name, 255);
                        printf("\tpreference: %2d weight: %2d port: %d host: %s\n",
                                        pref, weight, port, name);

                        pos += len;
                }
        }

        return 0;
}
