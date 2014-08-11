/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2008-2011 Lennart Poettering
  Copyright 2014 Tom Gundersen

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

#include "sd-rtnl.h"
#include "rtnl-util.h"
#include "macro.h"
#include "local-addresses.h"

static int address_compare(const void *_a, const void *_b) {
        const struct local_address *a = _a, *b = _b;

        /* Order lowest scope first, IPv4 before IPv6, lowest interface index first */

        if (a->scope < b->scope)
                return -1;
        if (a->scope > b->scope)
                return 1;

        if (a->family == AF_INET && b->family == AF_INET6)
                return -1;
        if (a->family == AF_INET6 && b->family == AF_INET)
                return 1;

        if (a->ifindex < b->ifindex)
                return -1;
        if (a->ifindex > b->ifindex)
                return 1;

        return 0;
}

int local_addresses(sd_rtnl *context, int ifindex, struct local_address **ret) {
        _cleanup_rtnl_message_unref_ sd_rtnl_message *req = NULL, *reply = NULL;
        _cleanup_rtnl_unref_ sd_rtnl *rtnl = NULL;
        _cleanup_free_ struct local_address *list = NULL;
        size_t n_list = 0, n_allocated = 0;
        sd_rtnl_message *m;
        int r;

        assert(ret);

        if (context)
                rtnl = sd_rtnl_ref(context);
        else {
                r = sd_rtnl_open(&rtnl, 0);
                if (r < 0)
                        return r;
        }

        r = sd_rtnl_message_new_addr(rtnl, &req, RTM_GETADDR, 0, AF_UNSPEC);
        if (r < 0)
                return r;

        r = sd_rtnl_call(rtnl, req, 0, &reply);
        if (r < 0)
                return r;

        for (m = reply; m; m = sd_rtnl_message_next(m)) {
                struct local_address *a;
                unsigned char flags;
                uint16_t type;
                int ifi;

                r = sd_rtnl_message_get_errno(m);
                if (r < 0)
                        return r;

                r = sd_rtnl_message_get_type(m, &type);
                if (r < 0)
                        return r;

                if (type != RTM_NEWADDR)
                        continue;

                r = sd_rtnl_message_addr_get_ifindex(m, &ifi);
                if (r < 0)
                        return r;

                if (ifindex != 0 && ifi != ifindex)
                        continue;

                r = sd_rtnl_message_addr_get_flags(m, &flags);
                if (r < 0)
                        return r;

                if (flags & IFA_F_DEPRECATED)
                        continue;

                if (!GREEDY_REALLOC(list, n_allocated, n_list+1))
                        return -ENOMEM;

                a = list + n_list;

                r = sd_rtnl_message_addr_get_scope(m, &a->scope);
                if (r < 0)
                        return r;

                if (ifindex == 0 && (a->scope == RT_SCOPE_HOST || a->scope == RT_SCOPE_NOWHERE))
                        continue;

                r = sd_rtnl_message_addr_get_family(m, &a->family);
                if (r < 0)
                        return r;

                switch (a->family) {

                case AF_INET:
                        r = sd_rtnl_message_read_in_addr(m, IFA_LOCAL, &a->address.in);
                        if (r < 0) {
                                r = sd_rtnl_message_read_in_addr(m, IFA_ADDRESS, &a->address.in);
                                if (r < 0)
                                        continue;
                        }
                        break;

                case AF_INET6:
                        r = sd_rtnl_message_read_in6_addr(m, IFA_LOCAL, &a->address.in6);
                        if (r < 0) {
                                r = sd_rtnl_message_read_in6_addr(m, IFA_ADDRESS, &a->address.in6);
                                if (r < 0)
                                        continue;
                        }
                        break;

                default:
                        continue;
                }

                a->ifindex = ifi;

                n_list++;
        };

        if (n_list)
                qsort(list, n_list, sizeof(struct local_address), address_compare);

        *ret = list;
        list = NULL;

        return (int) n_list;
}
