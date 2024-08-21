/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/if_addrlabel.h>

#include "sd-netlink.h"

#include "format-table.h"
#include "in-addr-util.h"
#include "networkctl.h"
#include "networkctl-address-label.h"

static int dump_address_labels(sd_netlink *rtnl) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL, *reply = NULL;
        _cleanup_(table_unrefp) Table *table = NULL;
        TableCell *cell;
        int r;

        assert(rtnl);

        r = sd_rtnl_message_new_addrlabel(rtnl, &req, RTM_GETADDRLABEL, 0, AF_INET6);
        if (r < 0)
                return log_error_errno(r, "Could not allocate RTM_GETADDRLABEL message: %m");

        r = sd_netlink_message_set_request_dump(req, true);
        if (r < 0)
                return r;

        r = sd_netlink_call(rtnl, req, 0, &reply);
        if (r < 0)
                return r;

        table = table_new("label", "prefix/prefixlen");
        if (!table)
                return log_oom();

        if (arg_full)
                table_set_width(table, 0);

        r = table_set_sort(table, (size_t) 0);
        if (r < 0)
                return r;

        assert_se(cell = table_get_cell(table, 0, 0));
        (void) table_set_align_percent(table, cell, 100);
        (void) table_set_ellipsize_percent(table, cell, 100);

        assert_se(cell = table_get_cell(table, 0, 1));
        (void) table_set_align_percent(table, cell, 100);

        for (sd_netlink_message *m = reply; m; m = sd_netlink_message_next(m)) {
                struct in6_addr prefix;
                uint8_t prefixlen;
                uint32_t label;

                r = sd_netlink_message_get_errno(m);
                if (r < 0) {
                        log_error_errno(r, "Failed to get netlink message, ignoring: %m");
                        continue;
                }

                r = sd_netlink_message_read_u32(m, IFAL_LABEL, &label);
                if (r < 0 && r != -ENODATA) {
                        log_error_errno(r, "Could not read IFAL_LABEL, ignoring: %m");
                        continue;
                }

                r = sd_netlink_message_read_in6_addr(m, IFAL_ADDRESS, &prefix);
                if (r < 0)
                        continue;

                r = sd_rtnl_message_addrlabel_get_prefixlen(m, &prefixlen);
                if (r < 0)
                        continue;

                r = table_add_cell(table, NULL, TABLE_UINT32, &label);
                if (r < 0)
                        return table_log_add_error(r);

                r = table_add_cell_stringf(table, NULL, "%s/%u", IN6_ADDR_TO_STRING(&prefix), prefixlen);
                if (r < 0)
                        return table_log_add_error(r);
        }

        r = table_print(table, NULL);
        if (r < 0)
                return table_log_print_error(r);

        return 0;
}

int list_address_labels(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        int r;

        r = sd_netlink_open(&rtnl);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to netlink: %m");

        return dump_address_labels(rtnl);
}
