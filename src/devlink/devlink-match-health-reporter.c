/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/devlink.h>

#include "sd-netlink.h"

#include "log.h"

#include "devlink-match.h"

static int devlink_match_health_reporter_genl_read(
                sd_netlink_message *message,
                Manager *m,
                DevlinkMatch *match) {
        DevlinkMatchCommon *common = &match->common;
        int r;

        if (common->name)
                return -ENODATA;

        r = sd_netlink_message_enter_container(message, DEVLINK_ATTR_HEALTH_REPORTER);
        if (r < 0)
                return r;

        r = sd_netlink_message_read_string_strdup(message, DEVLINK_ATTR_HEALTH_REPORTER_NAME, &common->name);
        if (r < 0)
                return r;

        (void) sd_netlink_message_exit_container(message);

        return 0;
}

static int devlink_match_health_reporter_genl_append(sd_netlink_message *message, const DevlinkMatch *match) {
        const DevlinkMatchCommon *common = &match->common;
        int r;

        assert(common->name);

        r = sd_netlink_message_append_string(message, DEVLINK_ATTR_HEALTH_REPORTER_NAME, common->name);
        if (r < 0)
                return log_debug_errno(r, "Failed to append health reporter name to netlink message: %m");;

        return 0;
}

const DevlinkMatchVTable devlink_match_health_reporter_vtable = {
        .bit = DEVLINK_MATCH_BIT_COMMON_NAME,
        .free = devlink_match_common_name_free,
        .check = devlink_match_common_name_check,
        .log_prefix = devlink_match_common_name_log_prefix,
        .hash_func = devlink_match_common_name_hash_func,
        .compare_func = devlink_match_common_name_compare_func,
        .copy_func = devlink_match_common_name_copy_func,
        .genl_read = devlink_match_health_reporter_genl_read,
        .genl_append = devlink_match_health_reporter_genl_append,
};
