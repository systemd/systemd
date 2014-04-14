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

#include "ifconf.h"

int ifconf_acquire_addresses(struct address **_list, unsigned *_n_list) {
        _cleanup_rtnl_unref_ sd_rtnl *rtnl = NULL;
        _cleanup_rtnl_message_unref_ sd_rtnl_message *req = NULL, *reply = NULL;
        sd_rtnl_message *m;
        _cleanup_free_ struct address *list = NULL;
        struct address *new_list = NULL;
        unsigned n_list = 0;
        int r;

        r = sd_rtnl_open(&rtnl, 0);
        if (r < 0)
                return r;

        r = sd_rtnl_message_new_addr(rtnl, &req, RTM_GETADDR, 0, AF_UNSPEC);
        if (r < 0)
                return r;

        r = sd_rtnl_call(rtnl, req, 0, &reply);
        if (r < 0)
                return r;
        m = reply;

        do {
                uint16_t type;
                unsigned char scope;
                unsigned char flags;
                unsigned char family;
                int ifindex;
                union {
                        struct in_addr in;
                        struct in6_addr in6;
                } address;

                r = sd_rtnl_message_get_errno(m);
                if (r < 0)
                        return r;

                r = sd_rtnl_message_get_type(m, &type);
                if (r < 0)
                        return r;

                if (type != RTM_NEWADDR)
                        continue;

                r = sd_rtnl_message_addr_get_scope(m, &scope);
                if (r < 0)
                        return r;

                if (scope == RT_SCOPE_HOST || scope == RT_SCOPE_NOWHERE)
                        continue;

                r = sd_rtnl_message_addr_get_flags(m, &flags);
                if (r < 0)
                        return r;

                if (flags & IFA_F_DEPRECATED)
                        continue;

                r = sd_rtnl_message_addr_get_family(m, &family);
                if (r < 0)
                        return r;

                switch (family) {
                case AF_INET:
                        r = sd_rtnl_message_read_in_addr(m, IFA_LOCAL, &address.in);
                        if (r < 0) {
                                r = sd_rtnl_message_read_in_addr(m, IFA_ADDRESS, &address.in);
                                if (r < 0)
                                        continue;
                        }
                        break;
                case AF_INET6:
                        r = sd_rtnl_message_read_in6_addr(m, IFA_LOCAL, &address.in6);
                        if (r < 0) {
                                r = sd_rtnl_message_read_in6_addr(m, IFA_ADDRESS, &address.in6);
                                if (r < 0)
                                        continue;
                        }
                        break;
                default:
                        continue;
                }

                r = sd_rtnl_message_addr_get_ifindex(m, &ifindex);
                if (r < 0)
                        return r;

                new_list = realloc(list, (n_list+1) * sizeof(struct address));
                if (!new_list)
                        return -ENOMEM;
                else
                        list = new_list;

                assert_cc(sizeof(address) <= 16);

                list[n_list].family = family;
                list[n_list].scope = scope;
                memcpy(list[n_list].address, &address, sizeof(address));
                list[n_list].ifindex = ifindex;

                n_list++;

        } while ((m = sd_rtnl_message_next(m)));

        if (n_list)
                qsort(list, n_list, sizeof(struct address), address_compare);

        *_n_list = n_list;
        *_list = list;
        list = NULL;

        return 0;
}
