/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Tom Gundersen <teg@jklm.no>

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

#include <net/if.h>

#include "networkd.h"

#include "utf8.h"
#include "util.h"
#include "conf-parser.h"
#include "net-util.h"

int address_new(Network *network, Address **ret) {
        _cleanup_address_free_ Address *address = NULL;

        address = new0(Address, 1);
        if (!address)
                return -ENOMEM;

        address->network = network;

        LIST_PREPEND(addresses, network->addresses, address);

        *ret = address;
        address = NULL;

        return 0;
}

void address_free(Address *address) {
        if (!address)
                return;

        LIST_REMOVE(addresses, address->network->addresses, address);

        free(address->label);
        free(address);
}

int address_configure(Manager *manager, Address *address, Link *link) {
        _cleanup_sd_rtnl_message_unref_ sd_rtnl_message *req = NULL;
        int r;

        r = sd_rtnl_message_addr_new(RTM_NEWADDR, link->ifindex,
                        address->family, address->prefixlen,
                        IFA_F_PERMANENT, RT_SCOPE_UNIVERSE, &req);
        if (r < 0) {
                log_error("Could not allocate RTM_NEWADDR message: %s",
                          strerror(-r));
                return r;
        }

        r = sd_rtnl_message_append(req, IFA_LOCAL, &address->in_addr);
        if (r < 0) {
                log_error("Could not append IFA_LOCAL attribute: %s",
                          strerror(-r));
                return r;
        }

        if (address->family == AF_INET) {
                struct in_addr broadcast;

                broadcast.s_addr = address->in_addr.in.s_addr |
                                   htonl(0xfffffffflu >> address->prefixlen);

                r = sd_rtnl_message_append(req, IFA_BROADCAST, &broadcast);
                if (r < 0) {
                        log_error("Could not append IFA_BROADCAST attribute: %s",
                                  strerror(-r));
                        return r;
                }
        }

        if (address->label) {
                r = sd_rtnl_message_append(req, IFA_LABEL, address->label);
                if (r < 0) {
                        log_error("Could not append IFA_LABEL attribute: %s",
                                  strerror(-r));
                        return r;
                }
        }

        r = sd_rtnl_send_with_reply_and_block(manager->rtnl, req, 0, NULL);
        if (r < 0) {
                log_error("Could not configure address: %s", strerror(-r));
                return r != -EEXIST ? r : 0;
        }

        log_info("Configured interface address");

        return 0;
}

int config_parse_address(const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {
        _cleanup_address_free_ Address *n = NULL;
        _cleanup_free_ char *address = NULL;
        const char *e;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = address_new(userdata, &n);
        if (r < 0)
                return r;

        /* Address=address/prefixlen */

        /* prefixlen */
        e = strchr(rvalue, '/');
        if (e) {
                unsigned i;
                r = safe_atou(e + 1, &i);
                if (r < 0) {
                        log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                                   "Interface prefix length is invalid, "
                                   "ignoring assignment: %s", e + 1);
                        return 0;
                }

                n->prefixlen = (unsigned char) i;
                address = strndup(rvalue, e - rvalue);
                if (!address)
                        return log_oom();
        } else {
                address = strdup(rvalue);
                if (!address)
                        return log_oom();
        }

        r = net_parse_inaddr(address, &n->family, &n->in_addr);
        if (r < 0) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Address is invalid, ignoring assignment: %s", address);
                return 0;
        }

        n = NULL;

        return 0;
}
