/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/genetlink.h>

#include "sd-netlink.h"

#include "alloc-util.h"
#include "netlink-genl.h"
#include "netlink-internal.h"
#include "netlink-types.h"

typedef struct GenericNetlinkFamily {
        sd_netlink *genl;

        const NLAPolicySet *policy_set;

        uint16_t id; /* a.k.a nlmsg_type */
        char *name;
        uint32_t version;
        uint32_t additional_header_size;
        Hashmap *multicast_group_by_name;
} GenericNetlinkFamily;

static const GenericNetlinkFamily nlctrl_static = {
        .id = GENL_ID_CTRL,
        .name = (char*) CTRL_GENL_NAME,
        .version = 0x01,
};

static GenericNetlinkFamily *genl_family_free(GenericNetlinkFamily *f) {
        if (!f)
                return NULL;

        if (f->genl) {
                if (f->id > 0)
                        hashmap_remove(f->genl->genl_family_by_id, UINT_TO_PTR(f->id));
                if (f->name)
                        hashmap_remove(f->genl->genl_family_by_name, f->name);
        }

        free(f->name);
        hashmap_free(f->multicast_group_by_name);

        return mfree(f);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(GenericNetlinkFamily*, genl_family_free);

void genl_clear_family(sd_netlink *nl) {
        assert(nl);

        nl->genl_family_by_name = hashmap_free_with_destructor(nl->genl_family_by_name, genl_family_free);
        nl->genl_family_by_id = hashmap_free_with_destructor(nl->genl_family_by_id, genl_family_free);
}

static int genl_family_new_unsupported(
                sd_netlink *nl,
                const char *family_name,
                const NLAPolicySet *policy_set) {

        _cleanup_(genl_family_freep) GenericNetlinkFamily *f = NULL;
        int r;

        assert(nl);
        assert(family_name);
        assert(policy_set);

        /* Kernel does not support the genl family? To prevent from resolving the family name again,
         * let's store the family with zero id to indicate that. */

        f = new(GenericNetlinkFamily, 1);
        if (!f)
                return -ENOMEM;

        *f = (GenericNetlinkFamily) {
                .policy_set = policy_set,
        };

        f->name = strdup(family_name);
        if (!f->name)
                return -ENOMEM;

        r = hashmap_ensure_put(&nl->genl_family_by_name, &string_hash_ops, f->name, f);
        if (r < 0)
                return r;

        f->genl = nl;
        TAKE_PTR(f);
        return 0;
}

static int genl_family_new(
                sd_netlink *nl,
                const char *expected_family_name,
                const NLAPolicySet *policy_set,
                sd_netlink_message *message,
                const GenericNetlinkFamily **ret) {

        _cleanup_(genl_family_freep) GenericNetlinkFamily *f = NULL;
        const char *family_name;
        uint8_t cmd;
        int r;

        assert(nl);
        assert(expected_family_name);
        assert(policy_set);
        assert(message);
        assert(ret);

        f = new(GenericNetlinkFamily, 1);
        if (!f)
                return -ENOMEM;

        *f = (GenericNetlinkFamily) {
                .policy_set = policy_set,
        };

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

        if (!streq(f->name, expected_family_name))
                return -EINVAL;

        r = sd_netlink_message_read_u32(message, CTRL_ATTR_VERSION, &f->version);
        if (r < 0)
                return r;

        r = sd_netlink_message_read_u32(message, CTRL_ATTR_HDRSIZE, &f->additional_header_size);
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

                        if (group_id == 0) {
                                log_debug("sd-netlink: received multicast group '%s' for generic netlink family '%s' with id == 0, ignoring",
                                          group_name, f->name);
                                continue;
                        }

                        r = hashmap_ensure_put(&f->multicast_group_by_name, &string_hash_ops_free, group_name, UINT32_TO_PTR(group_id));
                        if (r < 0)
                                return r;

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
        *ret = TAKE_PTR(f);
        return 0;
}

static const NLAPolicySet *genl_family_get_policy_set(const GenericNetlinkFamily *family) {
        assert(family);

        if (family->policy_set)
                return family->policy_set;

        return genl_get_policy_set_by_name(family->name);
}

static int genl_message_new(
                sd_netlink *nl,
                const GenericNetlinkFamily *family,
                uint8_t cmd,
                sd_netlink_message **ret) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        const NLAPolicySet *policy_set;
        int r;

        assert(nl);
        assert(nl->protocol == NETLINK_GENERIC);
        assert(family);
        assert(ret);

        policy_set = genl_family_get_policy_set(family);
        if (!policy_set)
                return -EOPNOTSUPP;

        r = message_new_full(nl, family->id, policy_set,
                             sizeof(struct genlmsghdr) + family->additional_header_size, &m);
        if (r < 0)
                return r;

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
                const GenericNetlinkFamily **ret) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL, *reply = NULL;
        const NLAPolicySet *policy_set;
        int r;

        assert(nl);
        assert(nl->protocol == NETLINK_GENERIC);
        assert(ctrl);
        assert(name);
        assert(ret);

        policy_set = genl_get_policy_set_by_name(name);
        if (!policy_set)
                return -EOPNOTSUPP;

        r = genl_message_new(nl, ctrl, CTRL_CMD_GETFAMILY, &req);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_string(req, CTRL_ATTR_FAMILY_NAME, name);
        if (r < 0)
                return r;

        if (sd_netlink_call(nl, req, 0, &reply) < 0) {
                (void) genl_family_new_unsupported(nl, name, policy_set);
                return -EOPNOTSUPP;
        }

        return genl_family_new(nl, name, policy_set, reply, ret);
}

static int genl_family_get_by_name(sd_netlink *nl, const char *name, const GenericNetlinkFamily **ret) {
        const GenericNetlinkFamily *f, *ctrl;
        int r;

        assert(nl);
        assert(nl->protocol == NETLINK_GENERIC);
        assert(name);
        assert(ret);

        f = hashmap_get(nl->genl_family_by_name, name);
        if (f) {
                if (f->id == 0) /* kernel does not support the family. */
                        return -EOPNOTSUPP;

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

static int genl_family_get_by_id(sd_netlink *nl, uint16_t id, const GenericNetlinkFamily **ret) {
        const GenericNetlinkFamily *f;

        assert(nl);
        assert(nl->protocol == NETLINK_GENERIC);
        assert(ret);

        f = hashmap_get(nl->genl_family_by_id, UINT_TO_PTR(id));
        if (f) {
                *ret = f;
                return 0;
        }

        if (id == GENL_ID_CTRL) {
                *ret = &nlctrl_static;
                return 0;
        }

        return -ENOENT;
}

int genl_get_policy_set_and_header_size(
                sd_netlink *nl,
                uint16_t id,
                const NLAPolicySet **ret_policy_set,
                size_t *ret_header_size) {

        const GenericNetlinkFamily *f;
        int r;

        assert(nl);
        assert(nl->protocol == NETLINK_GENERIC);

        r = genl_family_get_by_id(nl, id, &f);
        if (r < 0)
                return r;

        if (ret_policy_set) {
                const NLAPolicySet *p;

                p = genl_family_get_policy_set(f);
                if (!p)
                        return -EOPNOTSUPP;

                *ret_policy_set = p;
        }
        if (ret_header_size)
                *ret_header_size = sizeof(struct genlmsghdr) + f->additional_header_size;
        return 0;
}

int sd_genl_message_new(sd_netlink *nl, const char *family_name, uint8_t cmd, sd_netlink_message **ret) {
        const GenericNetlinkFamily *family;
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
        const GenericNetlinkFamily *family;
        uint16_t nlmsg_type;
        int r;

        assert_return(nl, -EINVAL);
        assert_return(nl->protocol == NETLINK_GENERIC, -EINVAL);
        assert_return(m, -EINVAL);
        assert_return(ret, -EINVAL);

        r = sd_netlink_message_get_type(m, &nlmsg_type);
        if (r < 0)
                return r;

        r = genl_family_get_by_id(nl, nlmsg_type, &family);
        if (r < 0)
                return r;

        *ret = family->name;
        return 0;
}

int sd_genl_message_get_command(sd_netlink *nl, sd_netlink_message *m, uint8_t *ret) {
        struct genlmsghdr *h;
        uint16_t nlmsg_type;
        size_t size;
        int r;

        assert_return(nl, -EINVAL);
        assert_return(nl->protocol == NETLINK_GENERIC, -EINVAL);
        assert_return(m, -EINVAL);
        assert_return(m->protocol == NETLINK_GENERIC, -EINVAL);
        assert_return(m->hdr, -EINVAL);
        assert_return(ret, -EINVAL);

        r = sd_netlink_message_get_type(m, &nlmsg_type);
        if (r < 0)
                return r;

        r = genl_get_policy_set_and_header_size(nl, nlmsg_type, NULL, &size);
        if (r < 0)
                return r;

        if (m->hdr->nlmsg_len < NLMSG_LENGTH(size))
                return -EBADMSG;

        h = NLMSG_DATA(m->hdr);

        *ret = h->cmd;
        return 0;
}

static int genl_family_get_multicast_group_id_by_name(const GenericNetlinkFamily *f, const char *name, uint32_t *ret) {
        void *p;

        assert(f);
        assert(name);

        p = hashmap_get(f->multicast_group_by_name, name);
        if (!p)
                return -ENOENT;

        if (ret)
                *ret = PTR_TO_UINT32(p);
        return 0;
}

int sd_genl_add_match(
                sd_netlink *nl,
                sd_netlink_slot **ret_slot,
                const char *family_name,
                const char *multicast_group_name,
                uint8_t command,
                sd_netlink_message_handler_t callback,
                sd_netlink_destroy_t destroy_callback,
                void *userdata,
                const char *description) {

        const GenericNetlinkFamily *f;
        uint32_t multicast_group_id;
        int r;

        assert_return(nl, -EINVAL);
        assert_return(nl->protocol == NETLINK_GENERIC, -EINVAL);
        assert_return(callback, -EINVAL);
        assert_return(family_name, -EINVAL);
        assert_return(multicast_group_name, -EINVAL);

        /* If command == 0, then all commands belonging to the multicast group trigger the callback. */

        r = genl_family_get_by_name(nl, family_name, &f);
        if (r < 0)
                return r;

        r = genl_family_get_multicast_group_id_by_name(f, multicast_group_name, &multicast_group_id);
        if (r < 0)
                return r;

        return netlink_add_match_internal(nl, ret_slot, &multicast_group_id, 1, f->id, command,
                                          callback, destroy_callback, userdata, description);
}

int sd_genl_socket_open(sd_netlink **ret) {
        return netlink_open_family(ret, NETLINK_GENERIC);
}
