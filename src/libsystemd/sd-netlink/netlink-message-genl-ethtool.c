/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/ethtool_netlink_generated.h>

#include "sd-netlink.h"

#include "assert-util.h"

int sd_genl_message_new_ethtool(
                sd_netlink *nl,
                uint8_t cmd,
                uint16_t header_attr,
                int ifindex,
                uint32_t ethtool_header_flags,
                sd_netlink_message **ret) {

        int r;

        assert_return(ifindex > 0, -EINVAL);
        assert_return(ret, -EINVAL);

        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *m = NULL;
        r = sd_genl_message_new(nl, ETHTOOL_GENL_NAME, cmd, &m);
        if (r < 0)
                return r;

        r = sd_netlink_message_open_container(m, header_attr);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(m, ETHTOOL_A_HEADER_DEV_INDEX, ifindex);
        if (r < 0)
                return r;

        if (ethtool_header_flags != 0) {
                r = sd_netlink_message_append_u32(m, ETHTOOL_A_HEADER_FLAGS, ethtool_header_flags);
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_close_container(m);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(m);
        return 0;
}
