/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-netlink.h"

#include "netlink-internal.h"
#include "netlink-types.h"

#define CTRL_GENL_NAME "nlctrl"

void genl_clear_family(sd_netlink *nl);

static inline bool message_is_generic(sd_netlink_message *m) {
        assert(m);
        assert(m->hdr);

        return m->protocol == NETLINK_GENERIC &&
                !IN_SET(m->hdr->nlmsg_type, NLMSG_DONE, NLMSG_ERROR);
}

int genl_get_type_system_by_id(sd_netlink *nl, uint16_t id, const NLTypeSystem **ret);
int genl_get_header_size(sd_netlink *nl, uint16_t id, size_t *ret);
