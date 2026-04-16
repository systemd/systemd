/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"
#include "sd-netlink.h"
#include "sd-varlink.h"

#include "ansi-color.h"
#include "dhcp-message-dump.h"
#include "log.h"
#include "networkctl.h"
#include "networkctl-dhcp-lease.h"
#include "networkctl-link-info.h"
#include "networkctl-util.h"
#include "strv.h"

int verb_dhcp_lease(int argc, char *argv[], uintptr_t _data, void *userdata) {
        int r;

        /* networkctl dhcp-lease INTERFACE [CODE[:TYPE] ...] */
        assert(argc >= 2);

        pager_open(arg_pager_flags);

        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        r = sd_netlink_open(&rtnl);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to netlink: %m");

        _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *vl = NULL;
        r = varlink_connect_networkd(&vl);
        if (r < 0)
                return r;

        const char *ifname = argv[1];

        _cleanup_(link_info_array_freep) LinkInfo *link = NULL;
        r = acquire_link_info(vl, rtnl, STRV_MAKE(ifname), &link);
        if (r < 0)
                return r;
        if (r == 0)
                return -EINVAL; /* already logged in acquire_link_info(). */
        if (r > 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Interface name '%s' matches multiple interfaces.", ifname);

        if (!link->dhcp_message)
                return log_error_errno(SYNTHETIC_ERRNO(ENODATA),
                                       "Interface '%s' does not have DHCPv4 lease.", link->name);

        if (sd_json_format_enabled(arg_json_format_flags)) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
                r = dhcp_message_build_json(link->dhcp_message, &v);
                if (r < 0)
                        return log_error_errno(r, "Failed to build JSON variant from DHCP message: %m");

                r = sd_json_variant_dump(v, arg_json_format_flags, /* f= */ NULL, /* prefix= */ NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to dump JSON variant: %m");

                return 0;
        }

        char **args = strv_skip(argv, 2);
        if (strv_isempty(args)) {
                printf("%s%sHeader:%s\n", ansi_highlight(), ansi_add_underline(), ansi_normal());
                r = dump_dhcp_header(link->dhcp_message);
                if (r < 0)
                        return r;

                printf("\n%s%sOptions:%s\n", ansi_highlight(), ansi_add_underline(), ansi_normal());
        }

        return dump_dhcp_options(link->dhcp_message, args);
}
