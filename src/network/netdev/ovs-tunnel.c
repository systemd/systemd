/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/if_arp.h>

#include "netdev.h"
#include "ovs-tunnel.h"
#include "parse-util.h"
#include "string-util.h"
#include "strv.h"

static void ovs_tunnel_init(NetDev *netdev) {
        OVSTunnel *t = OVS_TUNNEL(netdev);

        t->dont_fragment = -1;
        t->remote_family = AF_UNSPEC;
        t->local_family = AF_UNSPEC;
}

static void ovs_tunnel_done(NetDev *netdev) {
        OVSTunnel *t = OVS_TUNNEL(netdev);

        free(t->bridge);
        free(t->type);
}

static int ovs_tunnel_create(NetDev *netdev) {
#if !ENABLE_OPENVSWITCH
        return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EOPNOTSUPP),
                                        "Open vSwitch support not compiled in. Rebuild with -Dopenvswitch=enabled.");
#else
        /* OVS tunnels exist purely in the OVS dataplane — no kernel netdev is
         * created, so no RTM_NEWLINK arrives and set_ifindex is never called.
         * Mark READY immediately; the OVSDB create happens via the reconciler. */
        log_netdev_debug(netdev, "OVS tunnel queued for reconciliation");
        return netdev_enter_ready(netdev);
#endif
}

static int ovs_tunnel_verify(NetDev *netdev, const char *filename) {
        OVSTunnel *t = OVS_TUNNEL(netdev);

        assert(filename);

        if (!t->bridge)
                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                "%s: OVSTunnel without Bridge= is not valid. Ignoring.",
                                                filename);

        if (!t->type)
                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                "%s: OVSTunnel without Type= is not valid. Ignoring.",
                                                filename);

        if (t->remote_family == AF_UNSPEC)
                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                "%s: OVSTunnel without Remote= is not valid. Ignoring.",
                                                filename);

        if (t->local_family != AF_UNSPEC && t->local_family != t->remote_family)
                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                "%s: Local= and Remote= address families must match, ignoring.",
                                                filename);

        /* VXLAN VNI and Geneve VNI are 24-bit fields. GRE/STT keys are 32-bit.
         * Reject out-of-range values early instead of letting ovs-vswitchd return
         * an opaque OVSDB error at reconcile time. */
        if (t->key_set && (streq(t->type, "vxlan") || streq(t->type, "geneve")) && t->key > 0xFFFFFFu)
                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(ERANGE),
                                                "%s: Key=%" PRIu32 " out of range for Type=%s (24-bit VNI, max %u). Ignoring.",
                                                filename, t->key, t->type, 0xFFFFFFu);

        return 0;
}

int config_parse_ovs_tunnel_type(
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

        OVSTunnel *t = OVS_TUNNEL(ASSERT_PTR(userdata));

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                t->type = mfree(t->type);
                return 0;
        }

        if (!STR_IN_SET(rvalue, "vxlan", "geneve", "gre", "stt")) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Invalid OVS tunnel type '%s', ignoring.", rvalue);
                return 0;
        }

        return free_and_strdup_warn(&t->type, rvalue);
}

int config_parse_ovs_tunnel_address(
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

        OVSTunnel *t = OVS_TUNNEL(ASSERT_PTR(userdata));
        union in_addr_union buffer;
        int r, f;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                if (streq(lvalue, "Remote")) {
                        t->remote = IN_ADDR_NULL;
                        t->remote_family = AF_UNSPEC;
                } else {
                        t->local = IN_ADDR_NULL;
                        t->local_family = AF_UNSPEC;
                }
                return 0;
        }

        r = in_addr_from_string_auto(rvalue, &f, &buffer);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Invalid OVS tunnel address '%s', ignoring assignment: %m", rvalue);
                return 0;
        }

        if (streq(lvalue, "Remote")) {
                t->remote = buffer;
                t->remote_family = f;
        } else {
                t->local = buffer;
                t->local_family = f;
        }

        return 0;
}

int config_parse_ovs_tunnel_key(
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

        OVSTunnel *t = OVS_TUNNEL(ASSERT_PTR(userdata));
        uint32_t k;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                t->key = 0;
                t->key_set = false;
                return 0;
        }

        r = safe_atou32(rvalue, &k);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Invalid OVS tunnel key '%s', ignoring assignment: %m", rvalue);
                return 0;
        }

        t->key = k;
        t->key_set = true;
        return 0;
}

const NetDevVTable ovs_tunnel_vtable = {
        .object_size = sizeof(OVSTunnel),
        .init = ovs_tunnel_init,
        .done = ovs_tunnel_done,
        .sections = NETDEV_COMMON_SECTIONS "OVSTunnel\0",
        .create = ovs_tunnel_create,
        .create_type = NETDEV_CREATE_INDEPENDENT,
        .config_verify = ovs_tunnel_verify,
        .iftype = ARPHRD_ETHER,
        .skip_netdev_kind_check = true,
};
