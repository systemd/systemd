/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-network.h"

#include "fs-util.h"
#include "glyph-util.h"
#include "networkctl.h"
#include "networkctl-dump-util.h"
#include "networkctl-journal.h"
#include "networkctl-status-system.h"
#include "networkctl-util.h"
#include "sort-util.h"
#include "strv.h"

static int ifindex_str_compare_func(char * const *a, char * const *b) {
        size_t al, bl;
        int r;

        al = strlen_ptr(*a);
        bl = strlen_ptr(*b);

        r = CMP(al, bl);
        if (r != 0)
                return r;

        return strcmp_ptr(*a, *b);
}

static int get_netifs(char **ret) {
        _cleanup_strv_free_ char **netifs = NULL;
        _cleanup_free_ char *joined = NULL;
        int r;

        assert(ret);

        r = get_files_in_directory("/run/systemd/netif/links/", &netifs);
        if (IN_SET(r, 0, -ENOENT)) {
                *ret = NULL;
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to list network interfaces: %m");

        typesafe_qsort(netifs, strv_length(netifs), ifindex_str_compare_func);

        joined = strv_join(netifs, ", ");
        if (!joined)
                return log_oom();

        *ret = TAKE_PTR(joined);
        return 0;
}

int system_status(sd_netlink *rtnl, sd_hwdb *hwdb) {
        _cleanup_free_ char *operational_state = NULL, *online_state = NULL, *netifs_joined = NULL;
        _cleanup_strv_free_ char **dns = NULL, **ntp = NULL, **search_domains = NULL, **route_domains = NULL;
        const char *on_color_operational, *off_color_operational, *on_color_online;
        _cleanup_(table_unrefp) Table *table = NULL;
        int r;

        assert(rtnl);

        (void) sd_network_get_operational_state(&operational_state);
        operational_state_to_color(NULL, operational_state, &on_color_operational, &off_color_operational);

        (void) sd_network_get_online_state(&online_state);
        online_state_to_color(online_state, &on_color_online, NULL);

        table = table_new_vertical();
        if (!table)
                return log_oom();

        if (arg_full)
                table_set_width(table, 0);

        r = get_netifs(&netifs_joined);
        if (r < 0)
                return r;

        r = table_add_many(table,
                           TABLE_FIELD, "State",
                           TABLE_STRING, strna(operational_state),
                           TABLE_SET_COLOR, on_color_operational,
                           TABLE_FIELD, "Online state",
                           TABLE_STRING, online_state ?: "unknown",
                           TABLE_SET_COLOR, on_color_online);
        if (r < 0)
                return table_log_add_error(r);

        r = dump_addresses(rtnl, NULL, table, 0);
        if (r < 0)
                return r;

        r = dump_gateways(rtnl, hwdb, table, 0);
        if (r < 0)
                return r;

        (void) sd_network_get_dns(&dns);
        r = dump_list(table, "DNS", dns);
        if (r < 0)
                return r;

        (void) sd_network_get_search_domains(&search_domains);
        r = dump_list(table, "Search Domains", search_domains);
        if (r < 0)
                return r;

        (void) sd_network_get_route_domains(&route_domains);
        r = dump_list(table, "Route Domains", route_domains);
        if (r < 0)
                return r;

        (void) sd_network_get_ntp(&ntp);
        r = dump_list(table, "NTP", ntp);
        if (r < 0)
                return r;

        printf("%s%s%s Interfaces: %s\n",
               on_color_operational, special_glyph(SPECIAL_GLYPH_BLACK_CIRCLE), off_color_operational,
               strna(netifs_joined));

        r = table_print(table, NULL);
        if (r < 0)
                return table_log_print_error(r);

        return show_logs(0, NULL);
}
