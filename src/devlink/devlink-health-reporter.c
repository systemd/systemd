/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/devlink.h>

#include "sd-netlink.h"

#include "string-util.h"

#include "devlink.h"
#include "devlink-health-reporter.h"

int config_parse_devlink_health_reporter_grace_period(CONFIG_PARSER_ARGUMENTS) {
        DevlinkHealthReporter *health_reporter = data;
        int r;

        r = config_parse_uint64(unit, filename, line, section, section_line, lvalue, ltype,
                                rvalue, &health_reporter->grace_period, userdata);
        if (r < 0)
                return r;
        health_reporter->grace_period_valid = true;
        return 0;
}

int config_parse_devlink_health_reporter_auto_recover(CONFIG_PARSER_ARGUMENTS) {
        DevlinkHealthReporter *health_reporter = data;
        int r;

        r = config_parse_bool(unit, filename, line, section, section_line, lvalue, ltype,
                              rvalue, &health_reporter->auto_recover, userdata);
        if (r < 0)
                return r;
        health_reporter->auto_recover_valid = true;
        return 0;
}

int config_parse_devlink_health_reporter_auto_dump(CONFIG_PARSER_ARGUMENTS) {
        DevlinkHealthReporter *health_reporter = data;
        int r;

        r = config_parse_bool(unit, filename, line, section, section_line, lvalue, ltype,
                              rvalue, &health_reporter->auto_dump, userdata);
        if (r < 0)
                return r;
        health_reporter->auto_dump_valid = true;
        return 0;
}

static int devlink_health_reporter_grace_period_update(
                Devlink *devlink,
                sd_netlink_message *message,
                sd_netlink_message *req,
                bool *set_needed) {
        DevlinkHealthReporter *health_reporter = DEVLINK_HEALTH_REPORTER(devlink);
        uint64_t current_val, val = health_reporter->grace_period;
        int r;

        if (!health_reporter->grace_period_valid)
                return 0;

        r = sd_netlink_message_read_u64(message, DEVLINK_ATTR_HEALTH_REPORTER_GRACEFUL_PERIOD, &current_val);
        if (r < 0)
                return log_devlink_debug_errno(devlink, r, "Netlink message without grace period: %m");

        log_devlink_debug(devlink, "Grace period current value \"%" PRIu64 "\", desired value \"%" PRIu64 "\".", current_val, val);

        if (current_val == val)
                return 0;

        log_devlink_info(devlink, "Grace period value to be set: \"%" PRIu64 "\".", val);

        r = sd_netlink_message_append_u64(req, DEVLINK_ATTR_HEALTH_REPORTER_GRACEFUL_PERIOD, val);
        if (r < 0)
                return log_devlink_debug_errno(devlink, r, "Failed to append grace period to netlink message: %m");;

        *set_needed = true;
        return 0;
}

static int devlink_health_reporter_auto_recover_update(
                Devlink *devlink,
                sd_netlink_message *message,
                sd_netlink_message *req,
                bool *set_needed) {
        DevlinkHealthReporter *health_reporter = DEVLINK_HEALTH_REPORTER(devlink);
        bool current_val, val = health_reporter->auto_recover;
        uint8_t tmp;
        int r;

        if (!health_reporter->auto_recover_valid)
                return 0;

        r = sd_netlink_message_read_u8(message, DEVLINK_ATTR_HEALTH_REPORTER_AUTO_RECOVER, &tmp);
        if (r < 0)
                return log_devlink_debug_errno(devlink, r, "Netlink message without auto recover: %m");
        current_val = !!tmp;

        log_devlink_debug(devlink, "Auto recover current value \"%s\", desired value \"%s\".", true_false(current_val), true_false(val));

        if (current_val == val)
                return 0;

        log_devlink_info(devlink, "Auto recover value to be set: \"%s\".", true_false(val));

        r = sd_netlink_message_append_u8(req, DEVLINK_ATTR_HEALTH_REPORTER_AUTO_RECOVER, val);
        if (r < 0)
                return log_devlink_debug_errno(devlink, r, "Failed to append auto recover to netlink message: %m");;

        *set_needed = true;
        return 0;
}

static int devlink_health_reporter_auto_dump_update(
                Devlink *devlink,
                sd_netlink_message *message,
                sd_netlink_message *req,
                bool *set_needed) {
        DevlinkHealthReporter *health_reporter = DEVLINK_HEALTH_REPORTER(devlink);
        bool current_val, val = health_reporter->auto_recover;
        uint8_t tmp;
        int r;

        if (!health_reporter->auto_dump_valid)
                return 0;

        r = sd_netlink_message_read_u8(message, DEVLINK_ATTR_HEALTH_REPORTER_AUTO_DUMP, &tmp);
        if (r < 0)
                return log_devlink_debug_errno(devlink, r, "Netlink message without auto dump: %m");
        current_val = !!tmp;

        log_devlink_debug(devlink, "Auto dump current value \"%s\", desired value \"%s\".", true_false(current_val), true_false(val));

        if (current_val == val)
                return 0;

        log_devlink_info(devlink, "Auto dump value to be set: \"%s\".", true_false(val));

        r = sd_netlink_message_append_u8(req, DEVLINK_ATTR_HEALTH_REPORTER_AUTO_DUMP, val);
        if (r < 0)
                return log_devlink_debug_errno(devlink, r, "Failed to append auto dump to netlink message: %m");;

        *set_needed = true;
        return 0;
}

static int devlink_health_reporter_genl_cmd_get_msg_process(
                Devlink *devlink,
                DevlinkKey *lookup_key,
                sd_netlink_message *message) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *rep = NULL;
        bool set_needed = false;
        int r;

        r = devlink_genl_message_new(devlink, DEVLINK_CMD_HEALTH_REPORTER_SET, &req);
        if (r < 0)
                return log_devlink_debug_errno(devlink, r, "Failed to create netlink message: %m");;

        r = devlink_key_genl_append(req, lookup_key);
        if (r < 0)
                return r;

        r = sd_netlink_message_enter_container(message, DEVLINK_ATTR_HEALTH_REPORTER);
        if (r < 0)
                return log_devlink_debug_errno(devlink, r, "Netlink message without health reporter nest: %m");

        r = devlink_health_reporter_grace_period_update(devlink, message, req, &set_needed);
        if (r < 0)
                return r;

        r = devlink_health_reporter_auto_recover_update(devlink, message, req, &set_needed);
        if (r < 0)
                return r;

        r = devlink_health_reporter_auto_dump_update(devlink, message, req, &set_needed);
        if (r < 0)
                return r;

        (void) sd_netlink_message_exit_container(message);

        if (!set_needed)
                return DEVLINK_MONITOR_COMMAND_RETVAL_OK;

        r = sd_netlink_call(devlink->manager->genl, req, 0, &rep);
        if (r < 0)
                return log_devlink_error_errno(devlink, r, "Could not send health reporter set message: %m");

        r = sd_netlink_message_get_errno(rep);
        if (r < 0)
                return log_devlink_error_errno(devlink, r, "Health reporter could not be set: %m");

        log_devlink_info(devlink, "Set success");

        return DEVLINK_MONITOR_COMMAND_RETVAL_OK;
}

static const DevlinkMatchSet devlink_health_reporter_matchsets[] = {
        DEVLINK_MATCH_BIT_PORT_IFNAME | DEVLINK_MATCH_BIT_COMMON_NAME,
        DEVLINK_MATCH_BIT_DEV | DEVLINK_MATCH_BIT_COMMON_INDEX | DEVLINK_MATCH_BIT_PORT_SPLIT | DEVLINK_MATCH_BIT_COMMON_NAME,
        DEVLINK_MATCH_BIT_DEV | DEVLINK_MATCH_BIT_COMMON_NAME,
        0,
};

static const DevlinkMonitorCommand devlink_health_reporter_commands[] = {
        { DEVLINK_CMD_HEALTH_REPORTER_GET, devlink_health_reporter_genl_cmd_get_msg_process, true },
};

const DevlinkVTable devlink_health_reporter_vtable = {
        .object_size = sizeof(DevlinkHealthReporter),
        .sections = DEVLINK_COMMON_SECTIONS "HealthReporter\0",
        .matchsets = devlink_health_reporter_matchsets,
        .genl_monitor_cmds = devlink_health_reporter_commands,
        .genl_monitor_cmds_count = ELEMENTSOF(devlink_health_reporter_commands),
        .genl_need_periodic_enumeration = true,
};
