/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdbool.h>
#include <stdint.h>

#include "sd-netlink.h"

#include "netlink-types.h"

int message_new_empty(sd_netlink *nl, sd_netlink_message **ret);
int message_new_full(
                sd_netlink *nl,
                uint16_t nlmsg_type,
                const NLTypeSystem *type_system,
                size_t header_size,
                sd_netlink_message **ret);
int message_new(sd_netlink *nl, sd_netlink_message **ret, uint16_t type);
int message_new_synthetic_error(sd_netlink *nl, int error, uint32_t serial, sd_netlink_message **ret);
void message_seal(sd_netlink_message *m);
