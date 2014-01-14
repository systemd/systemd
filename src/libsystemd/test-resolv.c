/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2005-2008 Lennart Poettering

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

#include "sd-resolv.h"
#include "resolv-util.h"
#include "macro.h"

int main(int argc, char *argv[]) {
        int r = 1, ret;
        _cleanup_resolv_free_ sd_resolv_t *resolv = NULL;
        _cleanup_resolv_addrinfo_free_ struct addrinfo *ai = NULL;
        _cleanup_resolv_answer_free_ unsigned char *srv = NULL;
        sd_resolv_query_t *q1, *q2, *q3;
        struct addrinfo hints = {};
        struct sockaddr_in sa = {};
        char host[NI_MAXHOST] = "", serv[NI_MAXSERV] = "";

        signal(SIGCHLD, SIG_IGN);

        resolv = sd_resolv_new(2);
        if (!resolv)
                log_oom();

        /* Make a name -> address query */
        hints.ai_family = PF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        q1 = sd_resolv_getaddrinfo(resolv, argc >= 2 ? argv[1] : "www.heise.de", NULL, &hints);
        if (!q1)
                fprintf(stderr, "sd_resolv_getaddrinfo(): %s\n", strerror(errno));

        /* Make an address -> name query */
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = inet_addr(argc >= 3 ? argv[2] : "193.99.144.71");
        sa.sin_port = htons(80);

        q2 = sd_resolv_getnameinfo(resolv, (struct sockaddr*) &sa, sizeof(sa), 0, 1, 1);
        if (!q2)
                fprintf(stderr, "sd_resolv_getnameinfo(): %s\n", strerror(errno));

        /* Make a res_query() call */
        q3 = sd_resolv_res_query(resolv, "_xmpp-client._tcp.gmail.com", C_IN, T_SRV);
        if (!q3)
                fprintf(stderr, "sd_resolv_res_query(): %s\n", strerror(errno));

        /* Wait until the three queries are completed */
        while (!sd_resolv_isdone(resolv, q1) ||
               !sd_resolv_isdone(resolv, q2) ||
               !sd_resolv_isdone(resolv, q3)) {
                if (sd_resolv_wait(resolv, 1) < 0)
                        fprintf(stderr, "sd_resolv_wait(): %s\n", strerror(errno));
        }

        /* Interpret the result of the name -> addr query */
        ret = sd_resolv_getaddrinfo_done(resolv, q1, &ai);
        if (ret)
                fprintf(stderr, "error: %s %i\n", gai_strerror(ret), ret);
        else {
                struct addrinfo *i;

                for (i = ai; i; i = i->ai_next) {
                        char t[256];
                        const char *p = NULL;

                        if (i->ai_family == PF_INET)
                                p = inet_ntop(AF_INET, &((struct sockaddr_in*) i->ai_addr)->sin_addr, t, sizeof(t));
                        else if (i->ai_family == PF_INET6)
                                p = inet_ntop(AF_INET6, &((struct sockaddr_in6*) i->ai_addr)->sin6_addr, t, sizeof(t));

                        printf("%s\n", p);
                }
        }

        /* Interpret the result of the addr -> name query */
        ret = sd_resolv_getnameinfo_done(resolv, q2, host, sizeof(host), serv, sizeof(serv));
        if (ret)
                fprintf(stderr, "error: %s %i\n", gai_strerror(ret), ret);
        else
                printf("%s -- %s\n", host, serv);

        /* Interpret the result of the SRV lookup */
        ret = sd_resolv_res_done(resolv, q3, &srv);
        if (ret < 0) {
                fprintf(stderr, "error: %s %i\n", strerror(errno), ret);
        } else if (ret == 0) {
                fprintf(stderr, "No reply for SRV lookup\n");
        } else {
                int qdcount;
                int ancount;
                int len;
                const unsigned char *pos = srv + sizeof(HEADER);
                unsigned char *end = srv + ret;
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

        r = 0;

        return r;
}
