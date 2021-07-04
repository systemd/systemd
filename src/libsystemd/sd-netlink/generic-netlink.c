/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/genetlink.h>

#include "sd-netlink.h"

#include "alloc-util.h"
#include "generic-netlink.h"
#include "netlink-internal.h"

int sd_genl_socket_open(sd_netlink **ret) {
        return netlink_open_family(ret, NETLINK_GENERIC);
}

static int genl_message_new(sd_netlink *nl, const char *name, uint16_t nlmsg_type, uint8_t cmd, sd_netlink_message **ret) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        const NLTypeSystem *type_system;
        int r;

        assert(nl);
        assert(nl->protocol == NETLINK_GENERIC);
        assert(name);
        assert(ret);

        r = genl_get_type_system_by_name(name, &type_system);
        if (r < 0)
                return r;

        r = message_new_full(nl, nlmsg_type, type_system, sizeof(struct genlmsghdr), &m);
        if (r < 0)
                return r;

        *(struct genlmsghdr *) NLMSG_DATA(m->hdr) = (struct genlmsghdr) {
                .cmd = cmd,
                .version = 1,
        };

        *ret = TAKE_PTR(m);
        return 0;
}

static int lookup_nlmsg_type(sd_netlink *nl, const char *name, uint16_t *ret) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL, *reply = NULL;
        _cleanup_free_ char *n = NULL;
        uint16_t u;
        void *v;
        int r;

        assert(nl);
        assert(nl->protocol == NETLINK_GENERIC);
        assert(name);
        assert(ret);

        if (streq(name, CTRL_GENL_NAME)) {
                *ret = GENL_ID_CTRL;
                return 0;
        }

        v = hashmap_get(nl->genl_family_to_nlmsg_type, name);
        if (v) {
                *ret = PTR_TO_UINT(v);
                return 0;
        }

        r = genl_message_new(nl, CTRL_GENL_NAME, GENL_ID_CTRL, CTRL_CMD_GETFAMILY, &req);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_string(req, CTRL_ATTR_FAMILY_NAME, name);
        if (r < 0)
                return r;

        r = sd_netlink_call(nl, req, 0, &reply);
        if (r < 0)
                return r;

        r = sd_netlink_message_read_u16(reply, CTRL_ATTR_FAMILY_ID, &u);
        if (r < 0)
                return r;

        n = strdup(name);
        if (!n)
                return -ENOMEM;

        r = hashmap_ensure_put(&nl->genl_family_to_nlmsg_type, &string_hash_ops_free, n, UINT_TO_PTR(u));
        if (r < 0)
                return r;

        r = hashmap_ensure_put(&nl->nlmsg_type_to_genl_family, NULL, UINT_TO_PTR(u), n);
        if (r < 0) {
                hashmap_remove(nl->genl_family_to_nlmsg_type, n);
                return r;
        }

        TAKE_PTR(n);

        *ret = u;
        return 0;
}

int genl_family_get_name(sd_netlink *nl, uint16_t id, const char **ret) {
        void *p;

        assert(nl);
        assert(nl->protocol == NETLINK_GENERIC);
        assert(ret);

        if (id == GENL_ID_CTRL) {
                *ret = CTRL_GENL_NAME;
                return 0;
        }

        p = hashmap_get(nl->nlmsg_type_to_genl_family, UINT_TO_PTR(id));
        if (!p)
                return -ENOENT;

        *ret = p;
        return 0;
}

int sd_genl_message_new(sd_netlink *nl, const char *family_name, uint8_t cmd, sd_netlink_message **ret) {
        uint16_t nlmsg_type = 0;  /* Unnecessary initialization to appease gcc */
        int r;

        assert_return(nl, -EINVAL);
        assert_return(nl->protocol == NETLINK_GENERIC, -EINVAL);
        assert_return(family_name, -EINVAL);
        assert_return(ret, -EINVAL);

        r = lookup_nlmsg_type(nl, family_name, &nlmsg_type);
        if (r < 0)
                return r;

        return genl_message_new(nl, family_name, nlmsg_type, cmd, ret);
}

int sd_genl_message_get_family_name(sd_netlink *nl, sd_netlink_message *m, const char **ret) {
        uint16_t nlmsg_type;
        int r;

        assert_return(nl, -EINVAL);
        assert_return(nl->protocol == NETLINK_GENERIC, -EINVAL);
        assert_return(m, -EINVAL);
        assert_return(ret, -EINVAL);

        r = sd_netlink_message_get_type(m, &nlmsg_type);
        if (r < 0)
                return r;

        return genl_family_get_name(nl, nlmsg_type, ret);
}
