/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if.h>
#include <net/if_arp.h>
#include <unistd.h>

#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "networkd-link.h"
#include "networkd-lldp-rx.h"
#include "networkd-lldp-tx.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "tmpfile-util.h"

DEFINE_CONFIG_PARSE_ENUM(config_parse_lldp_mode, lldp_mode, LLDPMode, "Failed to parse LLDP= setting.");

static const char* const lldp_mode_table[_LLDP_MODE_MAX] = {
        [LLDP_MODE_NO] = "no",
        [LLDP_MODE_YES] = "yes",
        [LLDP_MODE_ROUTERS_ONLY] = "routers-only",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(lldp_mode, LLDPMode, LLDP_MODE_YES);

static bool link_lldp_rx_enabled(Link *link) {
        assert(link);

        if (link->flags & IFF_LOOPBACK)
                return false;

        if (link->iftype != ARPHRD_ETHER)
                return false;

        if (!link->network)
                return false;

        /* LLDP should be handled on bridge and bond slaves as those have a direct connection to their peers,
         * not on the bridge/bond master. Linux doesn't even (by default) forward lldp packets to the bridge
         * master. */
        if (link->kind && STR_IN_SET(link->kind, "bridge", "bond"))
                return false;

        return link->network->lldp_mode != LLDP_MODE_NO;
}

static void lldp_rx_handler(sd_lldp_rx *lldp_rx, sd_lldp_rx_event_t event, sd_lldp_neighbor *n, void *userdata) {
        Link *link = ASSERT_PTR(userdata);
        int r;

        (void) link_lldp_save(link);

        if (link->lldp_tx && event == SD_LLDP_RX_EVENT_ADDED) {
                /* If we received information about a new neighbor, restart the LLDP "fast" logic */

                log_link_debug(link, "Received LLDP datagram from previously unknown neighbor, restarting 'fast' LLDP transmission.");

                (void) sd_lldp_tx_stop(link->lldp_tx);
                r = sd_lldp_tx_start(link->lldp_tx);
                if (r < 0)
                        log_link_warning_errno(link, r, "Failed to restart LLDP transmission: %m");
        }
}

int link_lldp_rx_configure(Link *link) {
        int r;

        if (!link_lldp_rx_enabled(link))
                return 0;

        if (link->lldp_rx)
                return -EBUSY;

        r = sd_lldp_rx_new(&link->lldp_rx);
        if (r < 0)
                return r;

        r = sd_lldp_rx_attach_event(link->lldp_rx, link->manager->event, 0);
        if (r < 0)
                return r;

        r = sd_lldp_rx_set_ifindex(link->lldp_rx, link->ifindex);
        if (r < 0)
                return r;

        r = sd_lldp_rx_match_capabilities(link->lldp_rx,
                                          link->network->lldp_mode == LLDP_MODE_ROUTERS_ONLY ?
                                          SD_LLDP_SYSTEM_CAPABILITIES_ALL_ROUTERS :
                                          SD_LLDP_SYSTEM_CAPABILITIES_ALL);
        if (r < 0)
                return r;

        r = sd_lldp_rx_set_filter_address(link->lldp_rx, &link->hw_addr.ether);
        if (r < 0)
                return r;

        r = sd_lldp_rx_set_callback(link->lldp_rx, lldp_rx_handler, link);
        if (r < 0)
                return r;

        return 0;
}

int link_lldp_save(Link *link) {
        _cleanup_(unlink_and_freep) char *temp_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        sd_lldp_neighbor **l = NULL;
        int n = 0, r, i;

        assert(link);

        if (isempty(link->lldp_file))
                return 0; /* Do not update state file when running in test mode. */

        if (!link->lldp_rx) {
                (void) unlink(link->lldp_file);
                return 0;
        }

        r = sd_lldp_rx_get_neighbors(link->lldp_rx, &l);
        if (r < 0)
                return r;
        if (r == 0) {
                (void) unlink(link->lldp_file);
                return 0;
        }

        n = r;

        r = fopen_temporary(link->lldp_file, &f, &temp_path);
        if (r < 0)
                goto finish;

        (void) fchmod(fileno(f), 0644);

        for (i = 0; i < n; i++) {
                const void *p;
                le64_t u;
                size_t sz;

                r = sd_lldp_neighbor_get_raw(l[i], &p, &sz);
                if (r < 0)
                        goto finish;

                u = htole64(sz);
                fwrite(&u, 1, sizeof(u), f);
                fwrite(p, 1, sz, f);
        }

        r = fflush_and_check(f);
        if (r < 0)
                goto finish;

        r = conservative_rename(temp_path, link->lldp_file);
        if (r < 0)
                goto finish;

finish:
        if (r < 0)
                log_link_error_errno(link, r, "Failed to save LLDP data to %s: %m", link->lldp_file);

        if (l) {
                for (i = 0; i < n; i++)
                        sd_lldp_neighbor_unref(l[i]);
                free(l);
        }

        return r;
}
