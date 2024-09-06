/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Make sure the net/if.h header is included before any linux/ one */
#include <net/if.h>
#include <errno.h>
#include <linux/if_arp.h>
#include <linux/if_vlan.h>

#include "parse-util.h"
#include "vlan-util.h"
#include "vlan.h"

static int netdev_vlan_fill_message_create(NetDev *netdev, Link *link, sd_netlink_message *req) {
        assert(link);
        assert(req);

        struct ifla_vlan_flags flags = {};
        VLan *v = VLAN(netdev);
        int r;

        r = sd_netlink_message_append_u16(req, IFLA_VLAN_ID, v->id);
        if (r < 0)
                return r;

        if (v->protocol >= 0) {
                r = sd_netlink_message_append_u16(req, IFLA_VLAN_PROTOCOL, htobe16(v->protocol));
                if (r < 0)
                        return r;
        }

        if (v->gvrp != -1) {
                flags.mask |= VLAN_FLAG_GVRP;
                SET_FLAG(flags.flags, VLAN_FLAG_GVRP, v->gvrp);
        }

        if (v->mvrp != -1) {
                flags.mask |= VLAN_FLAG_MVRP;
                SET_FLAG(flags.flags, VLAN_FLAG_MVRP, v->mvrp);
        }

        if (v->reorder_hdr != -1) {
                flags.mask |= VLAN_FLAG_REORDER_HDR;
                SET_FLAG(flags.flags, VLAN_FLAG_REORDER_HDR, v->reorder_hdr);
        }

        if (v->loose_binding != -1) {
                flags.mask |= VLAN_FLAG_LOOSE_BINDING;
                SET_FLAG(flags.flags, VLAN_FLAG_LOOSE_BINDING, v->loose_binding);
        }

        r = sd_netlink_message_append_data(req, IFLA_VLAN_FLAGS, &flags, sizeof(struct ifla_vlan_flags));
        if (r < 0)
                return r;

        if (!set_isempty(v->egress_qos_maps)) {
                struct ifla_vlan_qos_mapping *m;

                r = sd_netlink_message_open_container(req, IFLA_VLAN_EGRESS_QOS);
                if (r < 0)
                        return r;

                SET_FOREACH(m, v->egress_qos_maps) {
                        r = sd_netlink_message_append_data(req, IFLA_VLAN_QOS_MAPPING, m, sizeof(struct ifla_vlan_qos_mapping));
                        if (r < 0)
                                return r;
                }

                r = sd_netlink_message_close_container(req);
                if (r < 0)
                        return r;
        }

        if (!set_isempty(v->ingress_qos_maps)) {
                struct ifla_vlan_qos_mapping *m;

                r = sd_netlink_message_open_container(req, IFLA_VLAN_INGRESS_QOS);
                if (r < 0)
                        return r;

                SET_FOREACH(m, v->ingress_qos_maps) {
                        r = sd_netlink_message_append_data(req, IFLA_VLAN_QOS_MAPPING, m, sizeof(struct ifla_vlan_qos_mapping));
                        if (r < 0)
                                return r;
                }

                r = sd_netlink_message_close_container(req);
                if (r < 0)
                        return r;
        }

        return 0;
}

static void vlan_qos_maps_hash_func(const struct ifla_vlan_qos_mapping *x, struct siphash *state) {
        siphash24_compress_typesafe(x->from, state);
        siphash24_compress_typesafe(x->to, state);
}

static int vlan_qos_maps_compare_func(const struct ifla_vlan_qos_mapping *a, const struct ifla_vlan_qos_mapping *b) {
        int r;

        r = CMP(a->from, b->from);
        if (r != 0)
                return r;

        return CMP(a->to, b->to);
}

DEFINE_PRIVATE_HASH_OPS_WITH_KEY_DESTRUCTOR(
                vlan_qos_maps_hash_ops,
                struct ifla_vlan_qos_mapping,
                vlan_qos_maps_hash_func,
                vlan_qos_maps_compare_func,
                free);

int config_parse_vlan_qos_maps(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Set **s = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *s = set_free(*s);
                return 0;
        }

        for (const char *p = rvalue;;) {
                _cleanup_free_ struct ifla_vlan_qos_mapping *m = NULL;
                _cleanup_free_ char *w = NULL;
                unsigned from, to;

                r = extract_first_word(&p, &w, NULL, EXTRACT_CUNESCAPE|EXTRACT_UNQUOTE);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse %s, ignoring: %s", lvalue, rvalue);
                        return 0;
                }
                if (r == 0)
                        return 0;

                r = parse_range(w, &from, &to);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse %s, ignoring: %s", lvalue, w);
                        continue;
                }

                m = new(struct ifla_vlan_qos_mapping, 1);
                if (!m)
                        return log_oom();

                *m = (struct ifla_vlan_qos_mapping) {
                        .from = from,
                        .to = to,
                };

                r = set_ensure_consume(s, &vlan_qos_maps_hash_ops, TAKE_PTR(m));
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to store %s, ignoring: %s", lvalue, w);
                        continue;
                }
        }
}

static int netdev_vlan_verify(NetDev *netdev, const char *filename) {
        assert(filename);

        VLan *v = VLAN(netdev);

        if (v->id == VLANID_INVALID) {
                log_netdev_warning(netdev, "VLAN without valid Id (%"PRIu16") configured in %s.", v->id, filename);
                return -EINVAL;
        }

        return 0;
}

static void vlan_done(NetDev *netdev) {
        VLan *v = VLAN(netdev);

        set_free(v->egress_qos_maps);
        set_free(v->ingress_qos_maps);
}

static void vlan_init(NetDev *netdev) {
        VLan *v = VLAN(netdev);

        v->id = VLANID_INVALID;
        v->protocol = -1;
        v->gvrp = -1;
        v->mvrp = -1;
        v->loose_binding = -1;
        v->reorder_hdr = -1;
}

const NetDevVTable vlan_vtable = {
        .object_size = sizeof(VLan),
        .init = vlan_init,
        .sections = NETDEV_COMMON_SECTIONS "VLAN\0",
        .fill_message_create = netdev_vlan_fill_message_create,
        .create_type = NETDEV_CREATE_STACKED,
        .config_verify = netdev_vlan_verify,
        .done = vlan_done,
        .iftype = ARPHRD_ETHER,
};
