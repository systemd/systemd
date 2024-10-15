/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "format-ifname.h"
#include "in-addr-util.h"
#include "local-addresses.h"
#include "networkctl-dump-util.h"
#include "stdio-util.h"
#include "strv.h"

int dump_list(Table *table, const char *key, char * const *l) {
        int r;

        assert(table);
        assert(key);

        if (strv_isempty(l))
                return 0;

        r = table_add_many(table,
                           TABLE_FIELD, key,
                           TABLE_STRV, l);
        if (r < 0)
                return table_log_add_error(r);

        return 0;
}

/* IEEE Organizationally Unique Identifier vendor string */
int ieee_oui(sd_hwdb *hwdb, const struct ether_addr *mac, char **ret) {
        _cleanup_free_ char *desc = NULL;
        const char *description;
        char modalias[STRLEN("OUI:XXYYXXYYXXYY") + 1];
        int r;

        assert(ret);

        if (!hwdb || !mac)
                return -EINVAL;

        /* skip commonly misused 00:00:00 (Xerox) prefix */
        if (memcmp(mac, "\0\0\0", 3) == 0)
                return -EINVAL;

        xsprintf(modalias, "OUI:" ETHER_ADDR_FORMAT_STR, ETHER_ADDR_FORMAT_VAL(*mac));

        r = sd_hwdb_get(hwdb, modalias, "ID_OUI_FROM_DATABASE", &description);
        if (r < 0)
                return r;

        desc = strdup(description);
        if (!desc)
                return -ENOMEM;

        *ret = TAKE_PTR(desc);

        return 0;
}

static int get_gateway_description(
                sd_netlink *rtnl,
                sd_hwdb *hwdb,
                int ifindex,
                int family,
                union in_addr_union *gateway,
                char **ret) {

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL, *reply = NULL;
        int r;

        assert(rtnl);
        assert(ifindex >= 0);
        assert(IN_SET(family, AF_INET, AF_INET6));
        assert(gateway);
        assert(ret);

        r = sd_rtnl_message_new_neigh(rtnl, &req, RTM_GETNEIGH, ifindex, family);
        if (r < 0)
                return r;

        r = sd_netlink_message_set_request_dump(req, true);
        if (r < 0)
                return r;

        r = sd_netlink_call(rtnl, req, 0, &reply);
        if (r < 0)
                return r;

        for (sd_netlink_message *m = reply; m; m = sd_netlink_message_next(m)) {
                union in_addr_union gw = IN_ADDR_NULL;
                struct ether_addr mac = ETHER_ADDR_NULL;
                uint16_t type;
                int ifi, fam;

                r = sd_netlink_message_get_errno(m);
                if (r < 0) {
                        log_error_errno(r, "Failed to get netlink message, ignoring: %m");
                        continue;
                }

                r = sd_netlink_message_get_type(m, &type);
                if (r < 0) {
                        log_error_errno(r, "Failed to get netlink message type, ignoring: %m");
                        continue;
                }

                if (type != RTM_NEWNEIGH) {
                        log_error("Got unexpected netlink message type %u, ignoring.", type);
                        continue;
                }

                r = sd_rtnl_message_neigh_get_family(m, &fam);
                if (r < 0) {
                        log_error_errno(r, "Failed to get rtnl family, ignoring: %m");
                        continue;
                }

                if (fam != family) {
                        log_error("Got invalid rtnl family %d, ignoring.", fam);
                        continue;
                }

                r = sd_rtnl_message_neigh_get_ifindex(m, &ifi);
                if (r < 0) {
                        log_error_errno(r, "Failed to get rtnl ifindex, ignoring: %m");
                        continue;
                }

                if (ifindex > 0 && ifi != ifindex)
                        continue;

                switch (fam) {

                case AF_INET:
                        r = sd_netlink_message_read_in_addr(m, NDA_DST, &gw.in);
                        if (r < 0)
                                continue;

                        break;

                case AF_INET6:
                        r = sd_netlink_message_read_in6_addr(m, NDA_DST, &gw.in6);
                        if (r < 0)
                                continue;

                        break;

                default:
                        assert_not_reached();
                }

                if (!in_addr_equal(fam, &gw, gateway))
                        continue;

                r = sd_netlink_message_read(m, NDA_LLADDR, sizeof(mac), &mac);
                if (r < 0)
                        continue;

                r = ieee_oui(hwdb, &mac, ret);
                if (r < 0)
                        continue;

                return 0;
        }

        return -ENODATA;
}

int dump_gateways(sd_netlink *rtnl, sd_hwdb *hwdb, Table *table, int ifindex) {
        _cleanup_free_ struct local_address *local_addrs = NULL;
        _cleanup_strv_free_ char **buf = NULL;
        int r, n;

        assert(rtnl);
        assert(table);

        n = local_gateways(rtnl, ifindex, AF_UNSPEC, &local_addrs);
        if (n <= 0)
                return n;

        FOREACH_ARRAY(local, local_addrs, n) {
                _cleanup_free_ char *description = NULL;

                r = get_gateway_description(rtnl, hwdb, local->ifindex, local->family, &local->address, &description);
                if (r < 0)
                        log_debug_errno(r, "Could not get description of gateway, ignoring: %m");

                /* Show interface name for the entry if we show entries for all interfaces */
                r = strv_extendf(&buf, "%s%s%s%s%s%s",
                                 IN_ADDR_TO_STRING(local->family, &local->address),
                                 description ? " (" : "",
                                 strempty(description),
                                 description ? ")" : "",
                                 ifindex <= 0 ? " on " : "",
                                 ifindex <= 0 ? FORMAT_IFNAME_FULL(local->ifindex, FORMAT_IFNAME_IFINDEX_WITH_PERCENT) : "");
                if (r < 0)
                        return log_oom();
        }

        return dump_list(table, "Gateway", buf);
}

int dump_addresses(
                sd_netlink *rtnl,
                sd_dhcp_lease *lease,
                Table *table,
                int ifindex) {

        _cleanup_free_ struct local_address *local_addrs = NULL;
        _cleanup_strv_free_ char **buf = NULL;
        struct in_addr dhcp4_address = {};
        int r, n;

        assert(rtnl);
        assert(table);

        n = local_addresses(rtnl, ifindex, AF_UNSPEC, &local_addrs);
        if (n <= 0)
                return n;

        if (lease)
                (void) sd_dhcp_lease_get_address(lease, &dhcp4_address);

        FOREACH_ARRAY(local, local_addrs, n) {
                struct in_addr server_address;
                bool dhcp4 = false;

                if (local->family == AF_INET && in4_addr_equal(&local->address.in, &dhcp4_address))
                        dhcp4 = sd_dhcp_lease_get_server_identifier(lease, &server_address) >= 0;

                r = strv_extendf(&buf, "%s%s%s%s%s%s",
                                 IN_ADDR_TO_STRING(local->family, &local->address),
                                 dhcp4 ? " (DHCPv4 via " : "",
                                 dhcp4 ? IN4_ADDR_TO_STRING(&server_address) : "",
                                 dhcp4 ? ")" : "",
                                 ifindex <= 0 ? " on " : "",
                                 ifindex <= 0 ? FORMAT_IFNAME_FULL(local->ifindex, FORMAT_IFNAME_IFINDEX_WITH_PERCENT) : "");
                if (r < 0)
                        return log_oom();
        }

        return dump_list(table, "Address", buf);
}
