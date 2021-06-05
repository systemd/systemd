/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>

#include "sd-event.h"
#include "sd-netlink.h"

#include "firewall-util.h"
#include "in-addr-util.h"
#include "list.h"

typedef struct ExposePort {
        int protocol;
        uint16_t host_port;
        uint16_t container_port;
        LIST_FIELDS(struct ExposePort, ports);
} ExposePort;

void expose_port_free_all(ExposePort *p);
int expose_port_parse(ExposePort **l, const char *s);

int expose_port_watch_rtnl(sd_event *event, int recv_fd, sd_netlink_message_handler_t handler, void *userdata, sd_netlink **ret);
int expose_port_send_rtnl(int send_fd);

int expose_port_execute(sd_netlink *rtnl, FirewallContext **fw_ctx, ExposePort *l, int af, union in_addr_union *exposed);
int expose_port_flush(FirewallContext **fw_ctx, ExposePort* l, int af, union in_addr_union *exposed);
