/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if.h>
#include <net/if_arp.h>

#include "sd-lldp-tx.h"

#include "networkd-link.h"
#include "networkd-lldp-tx.h"
#include "networkd-manager.h"
#include "parse-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"

static bool link_lldp_tx_enabled(Link *link) {
        assert(link);

        if (link->flags & IFF_LOOPBACK)
                return false;

        if (link->iftype != ARPHRD_ETHER)
                return false;

        if (!link->network)
                return false;

        if (link->kind && STR_IN_SET(link->kind, "bridge", "bond"))
                return false;

        return link->network->lldp_multicast_mode >= 0 &&
                link->network->lldp_multicast_mode < _SD_LLDP_MULTICAST_MODE_MAX;
}

int link_lldp_tx_configure(Link *link) {
        int r;

        assert(link);

        if (!link_lldp_tx_enabled(link))
                return 0;

        if (link->lldp_tx)
                return -EBUSY;

        r = sd_lldp_tx_new(&link->lldp_tx);
        if (r < 0)
                return r;

        r = sd_lldp_tx_attach_event(link->lldp_tx, link->manager->event, 0);
        if (r < 0)
                return r;

        r = sd_lldp_tx_set_ifindex(link->lldp_tx, link->ifindex);
        if (r < 0)
                return r;

        r = sd_lldp_tx_set_hwaddr(link->lldp_tx, &link->hw_addr.ether);
        if (r < 0)
                return r;

        assert(link->network);

        r = sd_lldp_tx_set_multicast_mode(link->lldp_tx, link->network->lldp_multicast_mode);
        if (r < 0)
                return r;

        r = sd_lldp_tx_set_capabilities(link->lldp_tx,
                                        SD_LLDP_SYSTEM_CAPABILITIES_STATION |
                                        SD_LLDP_SYSTEM_CAPABILITIES_BRIDGE |
                                        SD_LLDP_SYSTEM_CAPABILITIES_ROUTER,
                                        (link->network->ip_forward != ADDRESS_FAMILY_NO) ?
                                        SD_LLDP_SYSTEM_CAPABILITIES_ROUTER :
                                        SD_LLDP_SYSTEM_CAPABILITIES_STATION);
        if (r < 0)
                return r;

        r = sd_lldp_tx_set_port_description(link->lldp_tx, link->network->description);
        if (r < 0)
                return r;

        r = sd_lldp_tx_set_mud_url(link->lldp_tx, link->network->lldp_mudurl);
        if (r < 0)
                return r;

        return 0;
}

static const char * const lldp_multicast_mode_table[_SD_LLDP_MULTICAST_MODE_MAX] = {
        [SD_LLDP_MULTICAST_MODE_NEAREST_BRIDGE]  = "nearest-bridge",
        [SD_LLDP_MULTICAST_MODE_NON_TPMR_BRIDGE] = "non-tpmr-bridge",
        [SD_LLDP_MULTICAST_MODE_CUSTOMER_BRIDGE] = "customer-bridge",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(lldp_multicast_mode, sd_lldp_multicast_mode_t);

int config_parse_lldp_multicast_mode(
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

        sd_lldp_multicast_mode_t m, *mode = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(section);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue)) {
                *mode = _SD_LLDP_MULTICAST_MODE_INVALID;
                return 0;
        }

        r = parse_boolean(rvalue);
        if (r >= 0) {
                *mode = r == 0 ? _SD_LLDP_MULTICAST_MODE_INVALID : SD_LLDP_MULTICAST_MODE_NEAREST_BRIDGE;
                return 0;
        }

        m = lldp_multicast_mode_from_string(rvalue);
        if (m < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, m,
                           "Failed to parse %s=, ignoring assignment: %s", lvalue, rvalue);
                return 0;
        }

        *mode = m;
        return 0;
}
