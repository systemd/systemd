/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/genetlink.h>

#include "sd-netlink.h"

#include "alloc-util.h"
#include "generic-netlink.h"
#include "netlink-internal.h"
#include "string-table.h"

int sd_genl_socket_open(sd_netlink **ret) {
        return netlink_open_family(ret, NETLINK_GENERIC);
}

static int genl_message_new(
                sd_netlink *nl,
                GenlFamily family,
                uint16_t nlmsg_type,
                uint8_t cmd,
                sd_netlink_message **ret) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        const NLType *genl_cmd_type, *nl_type;
        const NLTypeSystem *type_system;
        struct genlmsghdr *genl;
        size_t size;
        int r;

        assert(nl);
        assert(family >= 0);
        assert(!IN_SET(family, GENL_FAMILY_DONE, GENL_FAMILY_ERROR));
        assert(family < _GENL_FAMILY_MAX);

        r = type_system_get_type(&genl_family_type_system_root, &genl_cmd_type, family);
        if (r < 0)
                return r;

        r = message_new_empty(nl, &m);
        if (r < 0)
                return r;

        size = NLMSG_SPACE(sizeof(struct genlmsghdr));
        m->hdr = malloc0(size);
        if (!m->hdr)
                return -ENOMEM;

        m->hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

        type_get_type_system(genl_cmd_type, &type_system);

        r = type_system_get_type(type_system, &nl_type, cmd);
        if (r < 0)
                return r;

        m->hdr->nlmsg_len = size;
        m->hdr->nlmsg_type = nlmsg_type;

        type_get_type_system(nl_type, &m->containers[0].type_system);
        genl = NLMSG_DATA(m->hdr);
        genl->cmd = cmd;
        genl->version = 1; /* all currently known families are version 1 */

        *ret = TAKE_PTR(m);

        return 0;
}

static int lookup_id(
                sd_netlink *nl,
                GenlFamily family,
                uint16_t *ret) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL, *reply = NULL;
        uint16_t u;
        void *v;
        int r;

        if (family == GENL_FAMILY_ID_CTRL) {
                *ret = GENL_ID_CTRL;
                return 0;
        }

        if (IN_SET(family, GENL_FAMILY_ERROR, GENL_FAMILY_DONE)) /* not really families */
                return -EINVAL;

        v = hashmap_get(nl->genl_family_to_nlmsg_type, INT_TO_PTR(family));
        if (v) {
                *ret = PTR_TO_UINT(v);
                return 0;
        }

        r = genl_message_new(nl, GENL_FAMILY_ID_CTRL, GENL_ID_CTRL, CTRL_CMD_GETFAMILY, &req);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_string(req, CTRL_ATTR_FAMILY_NAME, genl_family_to_string(family));
        if (r < 0)
                return r;

        r = sd_netlink_call(nl, req, 0, &reply);
        if (r < 0)
                return r;

        r = sd_netlink_message_read_u16(reply, CTRL_ATTR_FAMILY_ID, &u);
        if (r < 0)
                return r;

        r = hashmap_ensure_put(&nl->genl_family_to_nlmsg_type, NULL, INT_TO_PTR(family), UINT_TO_PTR(u));
        if (r < 0)
                return r;

        r = hashmap_ensure_put(&nl->nlmsg_type_to_genl_family, NULL, UINT_TO_PTR(u), INT_TO_PTR(family));
        if (r < 0)
                return r;

        *ret = u;
        return 0;
}

int sd_genl_message_new(
                sd_netlink *nl,
                const char *family,
                uint8_t cmd,
                sd_netlink_message **ret) {

        uint16_t id;
        GenlFamily f;
        int r;

        assert_return(nl, -EINVAL);
        assert_return(nl->protocol == NETLINK_GENERIC, -EINVAL);

        if (!family) /* NULL family shall be alias for id-ctrl */
                return genl_message_new(nl, GENL_FAMILY_ID_CTRL, GENL_ID_CTRL, cmd, ret);

        f = genl_family_from_string(family);
        if (f < 0)
                return f;

        r = lookup_id(nl, f, &id);
        if (r < 0)
                return r;

        return genl_message_new(nl, f, id, cmd, ret);
}

int nlmsg_type_to_genl_family(const sd_netlink *nl, uint16_t type, GenlFamily *ret) {
        void *p;

        assert(nl);
        assert(nl->protocol == NETLINK_GENERIC);
        assert(ret);

        if (type == NLMSG_ERROR)
                *ret = GENL_FAMILY_ERROR;
        else if (type == NLMSG_DONE)
                *ret = GENL_FAMILY_DONE;
        else if (type == GENL_ID_CTRL)
                *ret = GENL_FAMILY_ID_CTRL;
        else {
                p = hashmap_get(nl->nlmsg_type_to_genl_family, UINT_TO_PTR(type));
                if (!p)
                        return -EOPNOTSUPP;

                *ret = PTR_TO_INT(p);
        }

        return 0;
}

int sd_genl_message_get_family(
                const sd_netlink *nl,
                const sd_netlink_message *m,
                const char **ret) {

        uint16_t type;
        GenlFamily f;
        int r;

        assert_return(m, -EINVAL);
        assert_return(nl, -EINVAL);
        assert_return(nl->protocol == NETLINK_GENERIC, -EINVAL);

        r = sd_netlink_message_get_type(m, &type);
        if (r < 0)
                return r;

        r = nlmsg_type_to_genl_family(nl, type, &f);
        if (r < 0)
                return r;

        if (ret)
                *ret = genl_family_to_string(f);

        return 0;
}

static const char* const genl_family_table[_GENL_FAMILY_MAX] = {
        [GENL_FAMILY_ERROR] = "error",
        [GENL_FAMILY_DONE] = "done",
        [GENL_FAMILY_ID_CTRL] = "id-ctrl",
        [GENL_FAMILY_WIREGUARD] = "wireguard",
        [GENL_FAMILY_FOU] = "fou",
        [GENL_FAMILY_L2TP] = "l2tp",
        [GENL_FAMILY_MACSEC] = "macsec",
        [GENL_FAMILY_NL80211] = "nl80211",
};

DEFINE_STRING_TABLE_LOOKUP(genl_family, GenlFamily);
