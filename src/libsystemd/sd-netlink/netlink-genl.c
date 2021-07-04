/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/genetlink.h>

#include "sd-netlink.h"

#include "alloc-util.h"
#include "netlink-genl.h"
#include "netlink-internal.h"
#include "netlink-types.h"

typedef struct GenericNetlinkFamily {
        sd_netlink *genl;

        const NLTypeSystem *type_system;

        uint16_t id; /* a.k.a nlmsg_type */
        char *name;
        uint32_t version;
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

        return mfree(f);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(GenericNetlinkFamily*, genl_family_free);

void genl_clear_family(sd_netlink *nl) {
        assert(nl);

        nl->genl_family_by_name = hashmap_free_with_destructor(nl->genl_family_by_name, genl_family_free);
        nl->genl_family_by_id = hashmap_free_with_destructor(nl->genl_family_by_id, genl_family_free);
}

static int genl_family_new(
                sd_netlink *nl,
                const char *expected_family_name,
                const NLTypeSystem *type_system,
                sd_netlink_message *message,
                const GenericNetlinkFamily **ret) {

        _cleanup_(genl_family_freep) GenericNetlinkFamily *f = NULL;
        const char *family_name;
        int r;

        assert(nl);
        assert(expected_family_name);
        assert(type_system);
        assert(message);
        assert(ret);

        f = new(GenericNetlinkFamily, 1);
        if (!f)
                return -ENOMEM;

        *f = (GenericNetlinkFamily) {
                .type_system = type_system,
        };

        if (sd_netlink_message_is_error(message)) {
                int e;

                /* Kernel does not support the genl family? To prevent from resolving the family name
                 * again, let's store the family with zero id to indicate that. */

                e = sd_netlink_message_get_errno(message);
                if (e >= 0) /* Huh? */
                        e = -EOPNOTSUPP;

                f->name = strdup(expected_family_name);
                if (!f->name)
                        return e;

                if (hashmap_ensure_put(&nl->genl_family_by_name, &string_hash_ops, f->name, f) < 0)
                        return e;

                f->genl = nl;
                TAKE_PTR(f);
                return e;
        }

        r = sd_genl_message_get_family_name(nl, message, &family_name);
        if (r < 0)
                return r;

        if (!streq(family_name, CTRL_GENL_NAME))
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

static int genl_family_get_type_system(const GenericNetlinkFamily *family, const NLTypeSystem **ret) {
        assert(family);
        assert(ret);

        if (family->type_system) {
                *ret = family->type_system;
                return 0;
        }

        return genl_get_type_system_by_name(family->name, ret);
}

static int genl_message_new(
                sd_netlink *nl,
                const GenericNetlinkFamily *family,
                uint8_t cmd,
                sd_netlink_message **ret) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        const NLTypeSystem *type_system;
        int r;

        assert(nl);
        assert(nl->protocol == NETLINK_GENERIC);
        assert(family);
        assert(ret);

        r = genl_family_get_type_system(family, &type_system);
        if (r < 0)
                return r;

        r = message_new_full(nl, family->id, type_system, sizeof(struct genlmsghdr), &m);
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
        const NLTypeSystem *type_system;
        int r;

        assert(nl);
        assert(nl->protocol == NETLINK_GENERIC);
        assert(ctrl);
        assert(name);
        assert(ret);

        r = genl_get_type_system_by_name(name, &type_system);
        if (r < 0)
                return r;

        r = genl_message_new(nl, ctrl, CTRL_CMD_GETFAMILY, &req);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_string(req, CTRL_ATTR_FAMILY_NAME, name);
        if (r < 0)
                return r;

        r = sd_netlink_call(nl, req, 0, &reply);
        if (r < 0)
                return r;

        return genl_family_new(nl, name, type_system, reply, ret);
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

int genl_get_type_system_and_header_size(
                sd_netlink *nl,
                uint16_t id,
                const NLTypeSystem **ret_type_system,
                size_t *ret_header_size) {

        const GenericNetlinkFamily *f;
        int r;

        assert(nl);
        assert(nl->protocol == NETLINK_GENERIC);

        r = genl_family_get_by_id(nl, id, &f);
        if (r < 0)
                return r;

        if (ret_type_system) {
                r = genl_family_get_type_system(f, ret_type_system);
                if (r < 0)
                        return r;
        }
        if (ret_header_size)
                *ret_header_size = sizeof(struct genlmsghdr);
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

int sd_genl_socket_open(sd_netlink **ret) {
        return netlink_open_family(ret, NETLINK_GENERIC);
}
