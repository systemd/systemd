/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/devlink.h>

#include "sd-netlink.h"

#include "log.h"

#include "devlink-match.h"

static void devlink_match_param_free(DevlinkMatch *match) {
        devlink_match_name_free(&match->param.name);
}

static bool devlink_match_param_check(const DevlinkMatch *match, bool explicit) {
        return devlink_match_name_check(match->param.name);
}

static void devlink_match_param_log_prefix(char **buf, int *len, const DevlinkMatch *match) {
        devlink_match_name_log_prefix(buf, len, match->param.name);
}

static void devlink_match_param_hash_func(const DevlinkMatch *match, struct siphash *state) {
        devlink_match_name_hash_func(match->param.name, state);
}

static int devlink_match_param_compare_func(const DevlinkMatch *x, const DevlinkMatch *y) {
        return devlink_match_name_compare_func(x->param.name, y->param.name);
}

static void devlink_match_param_copy_func(DevlinkMatch *dst, const DevlinkMatch *src) {
        devlink_match_name_copy_func(&dst->param.name, src->param.name);
}

static int devlink_match_param_duplicate_func(DevlinkMatch *dst, const DevlinkMatch *src) {
        return devlink_match_name_duplicate_func(&dst->param.name, src->param.name);
}

static int devlink_match_param_genl_read(
                sd_netlink_message *message,
                Manager *m,
                DevlinkMatch *match) {
        DevlinkMatchParam *param = &match->param;
        int r;

        if (param->name)
                return -ENODATA;

        r = sd_netlink_message_enter_container(message, DEVLINK_ATTR_PARAM);
        if (r < 0)
                return r;

        r = sd_netlink_message_read_string_strdup(message, DEVLINK_ATTR_PARAM_NAME, &param->name);

        (void) sd_netlink_message_exit_container(message);

        return r < 0 ? r : 0;
}

static int devlink_match_param_genl_append(sd_netlink_message *message, const DevlinkMatch *match) {
        const DevlinkMatchParam *param = &match->param;
        int r;

        assert(param->name);

        r = sd_netlink_message_append_string(message, DEVLINK_ATTR_PARAM_NAME, param->name);
        if (r < 0)
                return log_debug_errno(r, "Failed to append param name to netlink message: %m");

        return 0;
}

const DevlinkMatchVTable devlink_match_param_vtable = {
        .bit = DEVLINK_MATCH_BIT_PARAM_NAME,
        .free = devlink_match_param_free,
        .check = devlink_match_param_check,
        .log_prefix = devlink_match_param_log_prefix,
        .hash_func = devlink_match_param_hash_func,
        .compare_func = devlink_match_param_compare_func,
        .copy_func = devlink_match_param_copy_func,
        .duplicate_func = devlink_match_param_duplicate_func,
        .genl_read = devlink_match_param_genl_read,
        .genl_append = devlink_match_param_genl_append,
};
