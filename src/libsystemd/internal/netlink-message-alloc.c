/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "format-util.h"
#include "memory-util.h"
#include "netlink-internal.h"
#include "netlink-message-alloc.h"
#include "netlink-types.h"

int message_new_empty(sd_netlink *nl, sd_netlink_message **ret) {
        sd_netlink_message *m;

        assert(nl);
        assert(ret);

        /* Note that 'nl' is currently unused, if we start using it internally we must take care to
         * avoid problems due to mutual references between buses and their queued messages. See sd-bus. */

        m = new(sd_netlink_message, 1);
        if (!m)
                return -ENOMEM;

        *m = (sd_netlink_message) {
                .n_ref = 1,
                .protocol = nl->protocol,
                .sealed = false,
        };

        *ret = m;
        return 0;
}

int message_new_full(
                sd_netlink *nl,
                uint16_t nlmsg_type,
                const NLTypeSystem *type_system,
                size_t header_size,
                sd_netlink_message **ret) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        size_t size;
        int r;

        assert(nl);
        assert(type_system);
        assert(ret);

        size = NLMSG_SPACE(header_size);
        assert(size >= sizeof(struct nlmsghdr));

        r = message_new_empty(nl, &m);
        if (r < 0)
                return r;

        m->containers[0].type_system = type_system;

        m->hdr = malloc0(size);
        if (!m->hdr)
                return -ENOMEM;

        m->hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
        m->hdr->nlmsg_len = size;
        m->hdr->nlmsg_type = nlmsg_type;

        *ret = TAKE_PTR(m);
        return 0;
}

int message_new(sd_netlink *nl, sd_netlink_message **ret, uint16_t type) {
        const NLTypeSystem *type_system;
        size_t size;
        int r;

        assert_return(nl, -EINVAL);
        assert_return(ret, -EINVAL);

        r = type_system_root_get_type_system_and_header_size(nl, type, &type_system, &size);
        if (r < 0)
                return r;

        return message_new_full(nl, type, type_system, size, ret);
}

int message_new_synthetic_error(sd_netlink *nl, int error, uint32_t serial, sd_netlink_message **ret) {
        struct nlmsgerr *err;
        int r;

        assert(error <= 0);

        r = message_new(nl, ret, NLMSG_ERROR);
        if (r < 0)
                return r;

        message_seal(*ret);
        (*ret)->hdr->nlmsg_seq = serial;

        err = NLMSG_DATA((*ret)->hdr);
        err->error = error;

        return 0;
}

void message_seal(sd_netlink_message *m) {
        assert(m);

        m->sealed = true;
}
