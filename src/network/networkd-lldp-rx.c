/* SPDX-License-Identifier: LGPL-2.1+ */

#include <net/if.h>
#include <net/if_arp.h>
#include <unistd.h>

#include "fd-util.h"
#include "fileio.h"
#include "networkd-link.h"
#include "networkd-lldp-rx.h"
#include "networkd-lldp-tx.h"
#include "networkd-network.h"
#include "string-table.h"
#include "string-util.h"
#include "tmpfile-util.h"

DEFINE_CONFIG_PARSE_ENUM(config_parse_lldp_mode, lldp_mode, LLDPMode, "Failed to parse LLDP= setting.");

static const char* const lldp_mode_table[_LLDP_MODE_MAX] = {
        [LLDP_MODE_NO] = "no",
        [LLDP_MODE_YES] = "yes",
        [LLDP_MODE_ROUTERS_ONLY] = "routers-only",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(lldp_mode, LLDPMode, LLDP_MODE_YES);

bool link_lldp_rx_enabled(Link *link) {
        assert(link);

        if (link->flags & IFF_LOOPBACK)
                return false;

        if (link->iftype != ARPHRD_ETHER)
                return false;

        if (!link->network)
                return false;

        /* LLDP should be handled on bridge slaves as those have a direct
         * connection to their peers not on the bridge master. Linux doesn't
         * even (by default) forward lldp packets to the bridge master.*/
        if (streq_ptr("bridge", link->kind))
                return false;

        return link->network->lldp_mode != LLDP_MODE_NO;
}

static void lldp_handler(sd_lldp *lldp, sd_lldp_event event, sd_lldp_neighbor *n, void *userdata) {
        Link *link = userdata;
        int r;

        assert(link);

        (void) link_lldp_save(link);

        if (link_lldp_emit_enabled(link) && event == SD_LLDP_EVENT_ADDED) {
                /* If we received information about a new neighbor, restart the LLDP "fast" logic */

                log_link_debug(link, "Received LLDP datagram from previously unknown neighbor, restarting 'fast' LLDP transmission.");

                r = link_lldp_emit_start(link);
                if (r < 0)
                        log_link_warning_errno(link, r, "Failed to restart LLDP transmission: %m");
        }
}

int link_lldp_rx_configure(Link *link) {
        int r;

        r = sd_lldp_new(&link->lldp);
        if (r < 0)
                return r;

        r = sd_lldp_set_ifindex(link->lldp, link->ifindex);
        if (r < 0)
                return r;

        r = sd_lldp_match_capabilities(link->lldp,
                                       link->network->lldp_mode == LLDP_MODE_ROUTERS_ONLY ?
                                       SD_LLDP_SYSTEM_CAPABILITIES_ALL_ROUTERS :
                                       SD_LLDP_SYSTEM_CAPABILITIES_ALL);
        if (r < 0)
                return r;

        r = sd_lldp_set_filter_address(link->lldp, &link->mac);
        if (r < 0)
                return r;

        r = sd_lldp_attach_event(link->lldp, NULL, 0);
        if (r < 0)
                return r;

        r = sd_lldp_set_callback(link->lldp, lldp_handler, link);
        if (r < 0)
                return r;

        r = link_update_lldp(link);
        if (r < 0)
                return r;

        return 0;
}

int link_update_lldp(Link *link) {
        int r;

        assert(link);

        if (!link->lldp)
                return 0;

        if (link->flags & IFF_UP) {
                r = sd_lldp_start(link->lldp);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Failed to start LLDP: %m");
                if (r > 0)
                        log_link_debug(link, "Started LLDP.");
        } else {
                r = sd_lldp_stop(link->lldp);
                if (r < 0)
                        return log_link_warning_errno(link, r, "Failed to stop LLDP: %m");
                if (r > 0)
                        log_link_debug(link, "Stopped LLDP.");
        }

        return r;
}

int link_lldp_save(Link *link) {
        _cleanup_free_ char *temp_path = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        sd_lldp_neighbor **l = NULL;
        int n = 0, r, i;

        assert(link);
        assert(link->lldp_file);

        if (!link->lldp) {
                (void) unlink(link->lldp_file);
                return 0;
        }

        r = sd_lldp_get_neighbors(link->lldp, &l);
        if (r < 0)
                goto finish;
        if (r == 0) {
                (void) unlink(link->lldp_file);
                goto finish;
        }

        n = r;

        r = fopen_temporary(link->lldp_file, &f, &temp_path);
        if (r < 0)
                goto finish;

        fchmod(fileno(f), 0644);

        for (i = 0; i < n; i++) {
                const void *p;
                le64_t u;
                size_t sz;

                r = sd_lldp_neighbor_get_raw(l[i], &p, &sz);
                if (r < 0)
                        goto finish;

                u = htole64(sz);
                (void) fwrite(&u, 1, sizeof(u), f);
                (void) fwrite(p, 1, sz, f);
        }

        r = fflush_and_check(f);
        if (r < 0)
                goto finish;

        if (rename(temp_path, link->lldp_file) < 0) {
                r = -errno;
                goto finish;
        }

finish:
        if (r < 0) {
                (void) unlink(link->lldp_file);
                if (temp_path)
                        (void) unlink(temp_path);

                log_link_error_errno(link, r, "Failed to save LLDP data to %s: %m", link->lldp_file);
        }

        if (l) {
                for (i = 0; i < n; i++)
                        sd_lldp_neighbor_unref(l[i]);
                free(l);
        }

        return r;
}
