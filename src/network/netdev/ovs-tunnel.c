/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/if_arp.h>

#include "netdev.h"
#include "ovs-tunnel.h"
#include "parse-util.h"
#include "string-util.h"

static void ovs_tunnel_init(NetDev *netdev) {
        OVSTunnel *t = OVS_TUNNEL(netdev);

        t->dont_fragment = -1;
}

static void ovs_tunnel_done(NetDev *netdev) {
        OVSTunnel *t = OVS_TUNNEL(netdev);

        free(t->bridge);
        free(t->type);
}

static int ovs_tunnel_create(NetDev *netdev) {
        /* OVS tunnels exist purely in the OVS dataplane — no kernel netdev is
         * created, so no RTM_NEWLINK arrives and set_ifindex is never called.
         * Mark READY immediately; the OVSDB create happens via the reconciler. */
        log_netdev_debug(netdev, "OVS tunnel queued for reconciliation");
        return netdev_enter_ready(netdev);
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

        if (t->remote.family == AF_UNSPEC)
                return log_netdev_warning_errno(netdev, SYNTHETIC_ERRNO(EINVAL),
                                                "%s: OVSTunnel without Remote= is not valid. Ignoring.",
                                                filename);

        if (t->local.family != AF_UNSPEC && t->local.family != t->remote.family)
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

        /* Deliberately not gated against a hardcoded allowlist. Like Bridge DatapathType=,
         * the value is passed through to OVSDB and validated server-side by ovs-vswitchd,
         * which is the only authority on which tunnel types its build actually supports: the
         * set varies by version (e.g. stt was dropped in OVS 3.0) and includes types beyond
         * the common ones (lisp, gtpu, bareudp, erspan, ...). A client-side list would
         * inevitably drift out of sync in both directions. An unsupported type surfaces as
         * the OVSDB transact error at reconcile time. */
        return free_and_strdup_warn(&t->type, rvalue);
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
        /* No keep_on_drop: unlike OVS bridges and internal ports, an OVS tunnel has no kernel
         * netdev (ovs_tunnel_create() enters READY immediately and there is no set_ifindex),
         * so there is never an RTM_DELLINK to survive and re-bind from. */
};
