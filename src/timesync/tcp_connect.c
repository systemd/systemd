/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netdb.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <endian.h>

/* FIXME: this file is a temporary solution and will be removed later; https://github.com/pendulum-project/nts-timesyncd/issues/1 */

int NTS_attach_socket(const char *host, int port, int type);

int NTS_attach_socket(const char *host, int port, int type) {
        struct addrinfo hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_socktype = type;

        struct addrinfo *info;
        if (getaddrinfo(host, NULL, &hints, &info) != 0)
                return -1;

        for (struct addrinfo *cur = info; cur; cur = cur->ai_next) {
                switch (cur->ai_family) {
                case AF_INET6:
                        ((struct sockaddr_in6*)cur->ai_addr)->sin6_port = htobe16(port);
                        break;
                case AF_INET:
                        ((struct sockaddr_in*)cur->ai_addr)->sin_port = htobe16(port);
                        break;
                default:
                        /* try a different sockaddr */
                        continue;
                }

                int sock = socket(cur->ai_family, type, 0);
                if (sock < 0) continue;

                if (connect(sock, cur->ai_addr, cur->ai_addrlen) != 0) {
                        (void) close(sock);
                        continue;
                }

                freeaddrinfo(info);

                int flags;
                if((flags = fcntl(sock, F_GETFL)) < 0 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
                        return close(sock), -2;
                }

                int status = 1;
                setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &status, sizeof(status));
                return sock;
        }

        freeaddrinfo(info);
        return -2;
}
