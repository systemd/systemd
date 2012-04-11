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
#include <sys/un.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#ifdef HAVE_LIBWRAP
#include <tcpd.h>
#endif

#include "tcpwrap.h"
#include "log.h"

bool socket_tcpwrap(int fd, const char *name) {
#ifdef HAVE_LIBWRAP
        struct request_info req;
        union {
                struct sockaddr sa;
                struct sockaddr_in in;
                struct sockaddr_in6 in6;
                struct sockaddr_un un;
                struct sockaddr_storage storage;
        } sa_union;
        socklen_t l = sizeof(sa_union);

        if (getsockname(fd, &sa_union.sa, &l) < 0)
                return true;

        if (sa_union.sa.sa_family != AF_INET &&
            sa_union.sa.sa_family != AF_INET6)
                return true;

        request_init(&req,
                     RQ_DAEMON, name,
                     RQ_FILE, fd,
                     NULL);

        fromhost(&req);

        if (!hosts_access(&req)) {
                log_warning("Connection refused by tcpwrap.");
                return false;
        }

        log_debug("Connection accepted by tcpwrap.");
#endif
        return true;
}
