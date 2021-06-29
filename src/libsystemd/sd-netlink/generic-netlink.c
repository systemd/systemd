/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/genetlink.h>

#include "sd-netlink.h"

#include "alloc-util.h"
#include "generic-netlink.h"
#include "netlink-internal.h"

typedef struct GenericNetlinkFamily {
        sd_netlink *genl;

        uint16_t id; /* a.k.a nlmsg_type */
        char *name;
        uint32_t version;
        uint32_t header_size;
        Hashmap *multicast_group_by_id;
        Hashmap *multicast_group_by_name;
} GenericNetlinkFamily;

static const GenericNetlinkFamily nlctrl_static = {
        .name = (char*) CTRL_GENL_NAME,
        .id = GENL_ID_CTRL,
        .version = 0x01,
};

static GenericNetlinkFamily *genl_family_free(GenericNetlinkFamily *f) {
        if (!f)
                return NULL;

        if (f->genl) {
                hashmap_remove(f->genl->genl_family_by_id, UINT_TO_PTR(f->id));
                if (f->name)
                        hashmap_remove(f->genl->genl_family_by_name, f->name);
        }

        free(f->name);
        hashmap_free(f->multicast_group_by_id);
        hashmap_free(f->multicast_group_by_name);

        return mfree(f);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(GenericNetlinkFamily*, genl_family_free);

void genl_clear_family(sd_netlink *nl) {
        assert(nl);

        nl->genl_family_by_name = hashmap_free_with_destructor(nl->genl_family_by_name, genl_family_free);
        nl->genl_family_by_id = hashmap_free_with_destructor(nl->genl_family_by_id, genl_family_free);
}

static int genl_family_new(sd_netlink *nl, sd_netlink_message *message, GenericNetlinkFamily **ret) {
        _cleanup_(genl_family_freep) GenericNetlinkFamily *f = NULL;
        const char *family_name;
        uint8_t cmd;
        int r;

        assert(nl);
        assert(message);

        f = new0(GenericNetlinkFamily, 1);
        if (!f)
                return -ENOMEM;

        r = sd_genl_message_get_family_name(nl, message, &family_name);
        if (r < 0)
                return r;

        if (!streq(family_name, CTRL_GENL_NAME))
                return -EINVAL;

        r = sd_genl_message_get_command(nl, message, &cmd);
        if (r < 0)
                return r;

        if (cmd != CTRL_CMD_NEWFAMILY)
                return -EINVAL;

        r = sd_netlink_message_read_u16(message, CTRL_ATTR_FAMILY_ID, &f->id);
        if (r < 0)
                return r;

        r = sd_netlink_message_read_string_strdup(message, CTRL_ATTR_FAMILY_NAME, &f->name);
        if (r < 0)
                return r;

        r = sd_netlink_message_read_u32(message, CTRL_ATTR_VERSION, &f->version);
        if (r < 0)
                return r;

        r = sd_netlink_message_read_u32(message, CTRL_ATTR_HDRSIZE, &f->header_size);
        if (r < 0)
                return r;

        r = sd_netlink_message_enter_container(message, CTRL_ATTR_MCAST_GROUPS);
        if (r >= 0) {
                for (uint16_t i = 0; i < UINT16_MAX; i++) {
                        _cleanup_free_ char *group_name = NULL;
                        uint32_t group_id;

                        r = sd_netlink_message_enter_array(message, i + 1);
                        if (r == -ENODATA)
                                break;
                        if (r < 0)
                                return r;

                        r = sd_netlink_message_read_u32(message, CTRL_ATTR_MCAST_GRP_ID, &group_id);
                        if (r < 0)
                                return r;

                        r = sd_netlink_message_read_string_strdup(message, CTRL_ATTR_MCAST_GRP_NAME, &group_name);
                        if (r < 0)
                                return r;

                        r = sd_netlink_message_exit_container(message);
                        if (r < 0)
                                return r;

                        r = hashmap_ensure_put(&f->multicast_group_by_id, NULL, UINT_TO_PTR(group_id + 1), group_name);
                        if (r < 0)
                                return r;

                        r = hashmap_ensure_put(&f->multicast_group_by_name, &string_hash_ops_free, group_name, UINT_TO_PTR(group_id + 1));
                        if (r < 0) {
                                hashmap_remove(f->multicast_group_by_id, UINT_TO_PTR(group_id + 1));
                                return r;
                        }

                        TAKE_PTR(group_name);
                }

                r = sd_netlink_message_exit_container(message);
                if (r < 0)
                        return r;
        }

        r = hashmap_ensure_put(&nl->genl_family_by_id, NULL, UINT_TO_PTR(f->id), f);
        if (r < 0)
                return r;

        r = hashmap_ensure_put(&nl->genl_family_by_name, &string_hash_ops, f->name, f);
        if (r < 0) {
                hashmap_remove(nl->genl_family_by_id, UINT_TO_PTR(f->id));
                return r;
        }

        f->genl = nl;

        if (ret)
                *ret = f;

        TAKE_PTR(f);
        return 0;
}

int sd_genl_socket_open(sd_netlink **ret) {
        return netlink_open_family(ret, NETLINK_GENERIC);
}

static int genl_message_new(
                sd_netlink *nl,
                const GenericNetlinkFamily *family,
                uint8_t cmd,
                sd_netlink_message **ret) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        const NLType *type;
        size_t size;
        int r;

        assert(nl);
        assert(nl->protocol == NETLINK_GENERIC);
        assert(family);
        assert(ret);

        r = type_system_root_get_type(nl, &type, family->id, cmd);
        if (r < 0)
                return r;

        if (type_get_type(type) != NETLINK_TYPE_NESTED)
                return -EINVAL;

        r = message_new_empty(nl, &m);
        if (r < 0)
                return r;

        size = NLMSG_SPACE(sizeof(struct genlmsghdr) + family->header_size);
        m->hdr = malloc0(size);
        if (!m->hdr)
                return -ENOMEM;

        m->hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

        m->hdr->nlmsg_len = size;
        m->hdr->nlmsg_type = family->id;

        type_get_type_system(type, &m->containers[0].type_system);

        *(struct genlmsghdr *) NLMSG_DATA(m->hdr) = (struct genlmsghdr) {
                .cmd = cmd,
                .version = family->version,
        };

        *ret = TAKE_PTR(m);
        return 0;
}

static int genl_family_get_by_name_internal(
                sd_netlink *nl,
                const GenericNetlinkFamily *ctrl,
                const char *name,
                GenericNetlinkFamily **ret) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL, *reply = NULL;
        int r;

        assert(nl);
        assert(nl->protocol == NETLINK_GENERIC);
        assert(ctrl);
        assert(name);

        r = genl_message_new(nl, ctrl, CTRL_CMD_GETFAMILY, &req);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_string(req, CTRL_ATTR_FAMILY_NAME, name);
        if (r < 0)
                return r;

        r = sd_netlink_call(nl, req, 0, &reply);
        if (r < 0)
                return r;

        return genl_family_new(nl, reply, ret);
}

static int genl_family_get_by_name(sd_netlink *nl, const char *name, GenericNetlinkFamily **ret) {
        GenericNetlinkFamily *f, *ctrl;
        int r;

        assert(nl);
        assert(nl->protocol == NETLINK_GENERIC);
        assert(name);

        f = hashmap_get(nl->genl_family_by_name, name);
        if (f) {
                if (ret)
                        *ret = f;
                return 0;
        }

        if (streq(name, CTRL_GENL_NAME))
                return genl_family_get_by_name_internal(nl, &nlctrl_static, CTRL_GENL_NAME, ret);

        ctrl = hashmap_get(nl->genl_family_by_name, CTRL_GENL_NAME);
        if (!ctrl) {
                r = genl_family_get_by_name_internal(nl, &nlctrl_static, CTRL_GENL_NAME, &ctrl);
                if (r < 0)
                        return r;
        }

        return genl_family_get_by_name_internal(nl, ctrl, name, ret);
}

int genl_family_get_name_by_id(sd_netlink *nl, uint16_t id, const char **ret) {
        GenericNetlinkFamily *f;

        assert(nl);
        assert(nl->protocol == NETLINK_GENERIC);

        f = hashmap_get(nl->genl_family_by_id, UINT_TO_PTR(id));
        if (f) {
                if (ret)
                        *ret = f->name;
                return 0;
        }

        if (id == GENL_ID_CTRL) {
                if (ret)
                        *ret = CTRL_GENL_NAME;
                return 0;
        }

        return -ENOENT;
}

int sd_genl_message_new(sd_netlink *nl, const char *family_name, uint8_t cmd, sd_netlink_message **ret) {
        GenericNetlinkFamily *family;
        int r;

        assert_return(nl, -EINVAL);
        assert_return(nl->protocol == NETLINK_GENERIC, -EINVAL);
        assert_return(family_name, -EINVAL);
        assert_return(ret, -EINVAL);

        r = genl_family_get_by_name(nl, family_name, &family);
        if (r < 0)
                return r;

        return genl_message_new(nl, family, cmd, ret);
}

int sd_genl_message_get_family_name(sd_netlink *nl, sd_netlink_message *m, const char **ret) {
        uint16_t nlmsg_type;
        int r;

        assert_return(nl, -EINVAL);
        assert_return(nl->protocol == NETLINK_GENERIC, -EINVAL);
        assert_return(m, -EINVAL);

        r = sd_netlink_message_get_type(m, &nlmsg_type);
        if (r < 0)
                return r;

        return genl_family_get_name_by_id(nl, nlmsg_type, ret);
}

int sd_genl_message_get_command(sd_netlink *nl, sd_netlink_message *m, uint8_t *ret) {
        int r;

        assert_return(nl, -EINVAL);
        assert_return(nl->protocol == NETLINK_GENERIC, -EINVAL);
        assert_return(m, -EINVAL);

        /* First, confirm this is netlink message for known generic netlink family. */
        r = sd_genl_message_get_family_name(nl, m, NULL);
        if (r < 0)
                return r;

        /* Second, check the message size is large enough. */
        if (m->hdr->nlmsg_len < NLMSG_LENGTH(sizeof(struct genlmsghdr)))
                return -EBADMSG;

        if (ret) {
                struct genlmsghdr *h = NLMSG_DATA(m->hdr);

                /* Finally, read the command. */
                *ret = h->cmd;
        }

        return 0;
}
