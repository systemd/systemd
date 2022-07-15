/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <arpa/inet.h>
#include <errno.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <resolv.h>
#include <stdio.h>

#include "sd-resolve.h"

#include "alloc-util.h"
#include "macro.h"
#include "socket-util.h"
#include "string-util.h"
#include "time-util.h"

#define TEST_TIMEOUT_USEC (20*USEC_PER_SEC)

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

        printf("Host: %s — Serv: %s\n", strna(host), strna(serv));
        return 0;
}

int main(int argc, char *argv[]) {
        _cleanup_(sd_resolve_query_unrefp) sd_resolve_query *q1 = NULL, *q2 = NULL;
        _cleanup_(sd_resolve_unrefp) sd_resolve *resolve = NULL;
        int r;

        struct addrinfo hints = {
                .ai_family = AF_UNSPEC,
                .ai_socktype = SOCK_STREAM,
                .ai_flags = AI_CANONNAME,
        };

        union sockaddr_union sa = {
                .in.sin_family = AF_INET,
                .in.sin_port = htobe16(80),
        };

        assert_se(sd_resolve_default(&resolve) >= 0);

        /* Test a floating resolver query */
        r = sd_resolve_getaddrinfo(resolve, NULL, "redhat.com", "http", NULL, getaddrinfo_handler, NULL);
        if (r < 0)
                log_error_errno(r, "sd_resolve_getaddrinfo(): %m");

        /* Make a name -> address query */
        r = sd_resolve_getaddrinfo(resolve, &q1, argc >= 2 ? argv[1] : "www.heise.de", NULL, &hints, getaddrinfo_handler, NULL);
        if (r < 0)
                log_error_errno(r, "sd_resolve_getaddrinfo(): %m");

        /* Make an address -> name query */
        sa.in.sin_addr.s_addr = inet_addr(argc >= 3 ? argv[2] : "193.99.144.71");
        r = sd_resolve_getnameinfo(resolve, &q2, &sa.sa, SOCKADDR_LEN(sa), 0, SD_RESOLVE_GET_BOTH, getnameinfo_handler, NULL);
        if (r < 0)
                log_error_errno(r, "sd_resolve_getnameinfo(): %m");

        /* Wait until all queries are completed */
        for (;;) {
                r = sd_resolve_wait(resolve, TEST_TIMEOUT_USEC);
                if (r == 0)
                        break;
                if (r == -ETIMEDOUT) {
                        /* Let's catch timeouts here, so that we can run safely in a CI that has no reliable DNS. Note
                         * that we invoke exit() directly here, as the stuck NSS call will not allow us to exit
                         * cleanly. */

                        log_notice_errno(r, "sd_resolve_wait() timed out, but that's OK");
                        exit(EXIT_SUCCESS);
                }
                if (r < 0) {
                        log_error_errno(r, "sd_resolve_wait(): %m");
                        assert_not_reached();
                }
        }

        return 0;
}
