/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/devlink.h>

#include "sd-netlink.h"

#include "log.h"

#include "devlink-match.h"

static void devlink_match_health_reporter_free(DevlinkMatch *match) {
        devlink_match_name_free(&match->health_reporter.name);
}

static bool devlink_match_health_reporter_check(const DevlinkMatch *match, bool is_explicit) {
        return devlink_match_name_check(match->health_reporter.name);
}

static void devlink_match_health_reporter_log_prefix(char **buf, int *len, const DevlinkMatch *match) {
        devlink_match_name_log_prefix(buf, len, match->health_reporter.name);
}

static void devlink_match_health_reporter_hash_func(const DevlinkMatch *match, struct siphash *state) {
        devlink_match_name_hash_func(match->health_reporter.name, state);
}

static int devlink_match_health_reporter_compare_func(const DevlinkMatch *x, const DevlinkMatch *y) {
        return devlink_match_name_compare_func(x->health_reporter.name, y->health_reporter.name);
}

static void devlink_match_health_reporter_copy_func(DevlinkMatch *dst, const DevlinkMatch *src) {
        devlink_match_name_copy_func(&dst->health_reporter.name, src->health_reporter.name);
}

static int devlink_match_health_reporter_duplicate_func(DevlinkMatch *dst, const DevlinkMatch *src) {
        return devlink_match_name_duplicate_func(&dst->health_reporter.name, src->health_reporter.name);
}

static int devlink_match_health_reporter_genl_read(
                sd_netlink_message *message,
                Manager *m,
                DevlinkMatch *match) {
        DevlinkMatchHealthReporter *health_reporter = &match->health_reporter;
        int r;

        if (health_reporter->name)
                return -ENODATA;

        r = sd_netlink_message_enter_container(message, DEVLINK_ATTR_HEALTH_REPORTER);
        if (r < 0)
                return r;

        r = sd_netlink_message_read_string_strdup(message, DEVLINK_ATTR_HEALTH_REPORTER_NAME, &health_reporter->name);
        (void) sd_netlink_message_exit_container(message);
        return r < 0 ? r : 0;
}

static int devlink_match_health_reporter_genl_append(sd_netlink_message *message, const DevlinkMatch *match) {
        const DevlinkMatchHealthReporter *health_reporter = &match->health_reporter;
        int r;

        assert(health_reporter->name);

        r = sd_netlink_message_append_string(message, DEVLINK_ATTR_HEALTH_REPORTER_NAME, health_reporter->name);
        if (r < 0)
                return log_debug_errno(r, "Failed to append health reporter name to netlink message: %m");

        return 0;
}

const DevlinkMatchVTable devlink_match_health_reporter_vtable = {
        .bit = DEVLINK_MATCH_BIT_HEALTH_REPORTER_NAME,
        .free = devlink_match_health_reporter_free,
        .check = devlink_match_health_reporter_check,
        .log_prefix = devlink_match_health_reporter_log_prefix,
        .hash_func = devlink_match_health_reporter_hash_func,
        .compare_func = devlink_match_health_reporter_compare_func,
        .copy_func = devlink_match_health_reporter_copy_func,
        .duplicate_func = devlink_match_health_reporter_duplicate_func,
        .genl_read = devlink_match_health_reporter_genl_read,
        .genl_append = devlink_match_health_reporter_genl_append,
};
