/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

typedef struct Address Address;
typedef struct Link Link;

int ipv4acd_configure(Link *link, Address *address, bool is_static);
int ipv4acd_update_mac(Link *link, struct hw_addr_data *old);
void ipv4acd_drop_mac(Link *link);
int ipv4acd_start(Link *link);
int ipv4acd_stop(Link *link);
