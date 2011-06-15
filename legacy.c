/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of nss-myhostname.

  Copyright 2008-2011 Lennart Poettering
  Copyright 2011 Robert millan

  nss-myhostname is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public License
  as published by the Free Software Foundation; either version 2.1 of
  the License, or (at your option) any later version.

  nss-myhostname is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with nss-myhostname; If not, see
  <http://www.gnu.org/licenses/>.
***/

#include <sys/types.h>
#include <errno.h>
#include <ifaddrs.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

#include "ifconf.h"

int ifconf_acquire_addresses(struct address **_list, unsigned *_n_list) {
        struct address *list = NULL;
        unsigned n_list = 0;
        struct ifaddrs *ifa = NULL;
        int r = 1;
        struct ifaddrs *i;
        int ifindex = 0;

        if (getifaddrs(&ifa) == -1) {
                r = -errno;
                goto finish;
        }

        for (i = ifa; i != NULL; i = i->ifa_next) {
                int af;
                const void *cp;
                struct sockaddr_in6 *in6 = (struct sockaddr_in6 *) i->ifa_addr;
                struct sockaddr_in *in = (struct sockaddr_in *) i->ifa_addr;

                if (! i->ifa_addr)
                        continue;

                af = i->ifa_addr->sa_family;

                if (af != AF_INET && af != AF_INET6)
                        continue;

                list = realloc(list, (n_list+1) * sizeof(struct address));
                if (!list) {
                        r = -ENOMEM;
                        goto finish;
                }

                if (af == AF_INET6)
                        cp = &in6->sin6_addr;
                else
                        cp = &in->sin_addr;

                list[n_list].family = af;
                list[n_list].scope = 0;
                memcpy(list[n_list].address, cp, PROTO_ADDRESS_SIZE(af));
                list[n_list].ifindex = ifindex++;
                n_list++;
        }

finish:
        if (ifa)
                freeifaddrs(ifa);

        if (r < 0)
                free(list);
        else {
                qsort(list, n_list, sizeof(struct address), address_compare);

                *_list = list;
                *_n_list = n_list;
        }

        return r;
}
