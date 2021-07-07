/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-netlink.h"

#include "netlink-internal.h"
#include "netlink-types.h"

#define CTRL_GENL_NAME "nlctrl"

static inline bool is_generic(int protocol, uint16_t nlmsg_type) {
        return protocol == NETLINK_GENERIC && !IN_SET(nlmsg_type, NLMSG_DONE, NLMSG_ERROR);
}

static inline bool message_is_generic(sd_netlink_message *m) {
        assert(m);
        assert(m->hdr);
        return is_generic(m->protocol, m->hdr->nlmsg_type);
}

void genl_clear_family(sd_netlink *nl);

int genl_get_type_system_and_header_size(
                sd_netlink *nl,
                uint16_t id,
                const NLTypeSystem **ret_type_system,
                size_t *ret_header_size);
