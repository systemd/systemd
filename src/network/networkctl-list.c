/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-network.h"

#include "format-table.h"
#include "netif-util.h"
#include "networkctl.h"
#include "networkctl-description.h"
#include "networkctl-link-info.h"
#include "networkctl-list.h"
#include "networkctl-util.h"

int list_links(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        _cleanup_(link_info_array_freep) LinkInfo *links = NULL;
        _cleanup_(table_unrefp) Table *table = NULL;
        TableCell *cell;
        int c, r;

        r = dump_description(argc, argv);
        if (r != 0)
                return r;

        r = acquire_bus(&bus);
        if (r < 0)
                return r;

        r = sd_netlink_open(&rtnl);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to netlink: %m");

        c = acquire_link_info(NULL, rtnl, argc > 1 ? argv + 1 : NULL, &links);
        if (c < 0)
                return c;

        pager_open(arg_pager_flags);

        table = table_new("idx", "link", "type", "operational", "setup");
        if (!table)
                return log_oom();

        if (arg_full)
                table_set_width(table, 0);

        table_set_header(table, arg_legend);
        table_set_ersatz_string(table, TABLE_ERSATZ_DASH);

        assert_se(cell = table_get_cell(table, 0, 0));
        (void) table_set_minimum_width(table, cell, 3);
        (void) table_set_weight(table, cell, 0);
        (void) table_set_ellipsize_percent(table, cell, 100);
        (void) table_set_align_percent(table, cell, 100);

        assert_se(cell = table_get_cell(table, 0, 1));
        (void) table_set_ellipsize_percent(table, cell, 100);

        FOREACH_ARRAY(link, links, c) {
                _cleanup_free_ char *setup_state = NULL, *operational_state = NULL;
                _cleanup_free_ char *t = NULL;
                const char *on_color_operational, *on_color_setup;

                (void) sd_network_link_get_operational_state(link->ifindex, &operational_state);
                operational_state_to_color(link->name, operational_state, &on_color_operational, NULL);

                (void) sd_network_link_get_setup_state(link->ifindex, &setup_state);
                setup_state_to_color(setup_state, &on_color_setup, NULL);

                r = net_get_type_string(link->sd_device, link->iftype, &t);
                if (r == -ENOMEM)
                        return log_oom();

                r = table_add_many(table,
                                   TABLE_INT, link->ifindex,
                                   TABLE_STRING, link->name,
                                   TABLE_STRING, t,
                                   TABLE_STRING, operational_state,
                                   TABLE_SET_COLOR, on_color_operational,
                                   TABLE_STRING, setup_state ?: "unmanaged",
                                   TABLE_SET_COLOR, on_color_setup);
                if (r < 0)
                        return table_log_add_error(r);
        }

        r = table_print(table, NULL);
        if (r < 0)
                return table_log_print_error(r);

        if (arg_legend)
                printf("\n%i links listed.\n", c);

        return 0;
}
