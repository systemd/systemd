/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright (C) 2014 Tom Gundersen
  Copyright (C) 2014 Susant Sahani

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

#include "async.h"
#include "lldp-port.h"
#include "lldp-network.h"

int lldp_port_start(lldp_port *p) {
        int r;

        assert_return(p, -EINVAL);

        r = lldp_network_bind_raw_socket(p->ifindex);
        if (r < 0)
                return r;

        p->rawfd = r;

        r = sd_event_add_io(p->event, &p->lldp_port_rx,
                            p->rawfd, EPOLLIN, lldp_receive_packet, p);
        if (r < 0) {
                log_debug("Failed to allocate event source: %s", strerror(-r));
                return r;
        }

        r = sd_event_source_set_priority(p->lldp_port_rx, p->event_priority);
        if (r < 0) {
                log_debug("Failed to set event priority: %s", strerror(-r));
                goto fail;
        }

        r = sd_event_source_set_description(p->lldp_port_rx, "lldp-port-rx");
        if (r < 0) {
                log_debug("Failed to set event name: %s", strerror(-r));
                goto fail;
        }

        return 0;

fail:
        lldp_port_stop(p);

        return r;
}

int lldp_port_stop(lldp_port *p) {

        assert_return(p, -EINVAL);

        p->rawfd = asynchronous_close(p->rawfd);
        p->lldp_port_rx = sd_event_source_unref(p->lldp_port_rx);

        return 0;
}

void lldp_port_free(lldp_port *p) {
        if (!p)
                return;

        lldp_port_stop(p);

        free(p->ifname);
        free(p);
}

int lldp_port_new(int ifindex,
                  const char *ifname,
                  const struct ether_addr *addr,
                  void *userdata,
                  lldp_port **ret) {
        _cleanup_free_ lldp_port *p = NULL;

        assert_return(ifindex, -EINVAL);
        assert_return(ifname, -EINVAL);
        assert_return(addr, -EINVAL);

        p = new0(lldp_port, 1);
        if (!p)
                return -ENOMEM;

        p->rawfd = -1;
        p->ifindex = ifindex;

        p->ifname = strdup(ifname);
        if (!p->ifname)
                return -ENOMEM;

        memcpy(&p->mac, addr, ETH_ALEN);

        p->userdata = userdata;

        *ret = p;

        p = NULL;

        return 0;
}
