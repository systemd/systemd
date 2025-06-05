/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/devlink.h>

#include "sd-netlink.h"

#include "netlink-types-devlink.h"
#include "parse-util.h"
#include "string-util.h"

#include "devlink.h"
#include "devlink-param.h"
#include "devlink-reload.h"

static void devlink_param_done(Devlink *devlink) {
        DevlinkParam *param = DEVLINK_PARAM(devlink);

        free(param->value);
}

static int devlink_param_config_verify(const Devlink *devlink, const char *filename) {
        const DevlinkParam *param = DEVLINK_CONST_PARAM(devlink);

        if (!param->value)
                return log_devlink_warning_errno(devlink, SYNTHETIC_ERRNO(EINVAL),
                                                 "%s: Value not specified. Ignoring.",
                                                 filename);
        return 0;
}

static int devlink_param_genl_process_u8(
                Devlink *devlink,
                sd_netlink_message *message,
                sd_netlink_message *req,
                bool *set_needed) {
        DevlinkParam *param = DEVLINK_PARAM(devlink);
        uint8_t val, current_val;
        int r;

        r = safe_atou8(param->value, &val);
        if (r < 0)
                return log_devlink_debug_errno(devlink, r, "Failed to parse u8 param value: %m");

        r = sd_netlink_message_read_u8(message, DEVLINK_ATTR_PARAM_VALUE_DATA, &current_val);
        if (r < 0)
                return log_devlink_debug_errno(devlink, r, "Netlink message without param value: %m");

        log_devlink_debug(devlink, "Current value \"%u\", desired value \"%u\".", current_val, val);

        if (current_val == val)
                return 0;

        log_devlink_info(devlink, "Value to be set: \"%s\".", param->value);

        r = sd_netlink_message_append_u8(req, DEVLINK_ATTR_PARAM_VALUE_DATA, val);
        if (r < 0)
                return log_devlink_debug_errno(devlink, r, "Failed to append param type to netlink message: %m");;

        *set_needed = true;
        return 0;
}

static int devlink_param_genl_process_u16(
                Devlink *devlink,
                sd_netlink_message *message,
                sd_netlink_message *req,
                bool *set_needed) {
        DevlinkParam *param = DEVLINK_PARAM(devlink);
        uint16_t val, current_val;
        int r;

        r = safe_atou16(param->value, &val);
        if (r < 0)
                return log_devlink_debug_errno(devlink, r, "Failed to parse u16 param value: %m");

        r = sd_netlink_message_read_u16(message, DEVLINK_ATTR_PARAM_VALUE_DATA, &current_val);
        if (r < 0)
                return log_devlink_debug_errno(devlink, r, "Netlink message without param value: %m");

        log_devlink_debug(devlink, "Current value \"%u\", desired value \"%u\".", current_val, val);

        if (current_val == val)
                return 0;

        log_devlink_info(devlink, "Value to be set: \"%s\".", param->value);

        r = sd_netlink_message_append_u16(req, DEVLINK_ATTR_PARAM_VALUE_DATA, val);
        if (r < 0)
                return log_devlink_debug_errno(devlink, r, "Failed to append param type to netlink message: %m");;

        *set_needed = true;
        return 0;
}

static int devlink_param_genl_process_u32(
                Devlink *devlink,
                sd_netlink_message *message,
                sd_netlink_message *req,
                bool *set_needed) {
        DevlinkParam *param = DEVLINK_PARAM(devlink);
        uint32_t val, current_val;
        int r;

        r = safe_atou32(param->value, &val);
        if (r < 0)
                return log_devlink_debug_errno(devlink, r, "Failed to parse u32 param value: %m");

        r = sd_netlink_message_read_u32(message, DEVLINK_ATTR_PARAM_VALUE_DATA, &current_val);
        if (r < 0)
                return log_devlink_debug_errno(devlink, r, "Netlink message without param value: %m");

        log_devlink_debug(devlink, "Current value \"%u\", desired value \"%u\".", current_val, val);

        if (current_val == val)
                return 0;

        log_devlink_info(devlink, "Value to be set: \"%s\".", param->value);

        r = sd_netlink_message_append_u32(req, DEVLINK_ATTR_PARAM_VALUE_DATA, val);
        if (r < 0)
                return log_devlink_debug_errno(devlink, r, "Failed to append param type to netlink message: %m");;

        *set_needed = true;
        return 0;
}

static int devlink_param_genl_process_string(
                Devlink *devlink,
                sd_netlink_message *message,
                sd_netlink_message *req,
                bool *set_needed) {
        DevlinkParam *param = DEVLINK_PARAM(devlink);
        const char *current_val;
        int r;

        r = sd_netlink_message_read_string(message, DEVLINK_ATTR_PARAM_VALUE_DATA, &current_val);
        if (r < 0)
                return log_devlink_debug_errno(devlink, r, "Netlink message without param value: %m");

        log_devlink_debug(devlink, "Current value \"%s\", desired value \"%s\".", current_val, param->value);

        if (!strcmp(current_val, param->value))
                return 0;

        log_devlink_info(devlink, "Value to be set: \"%s\".", param->value);

        r = sd_netlink_message_append_string(req, DEVLINK_ATTR_PARAM_VALUE_DATA, param->value);
        if (r < 0)
                return log_devlink_debug_errno(devlink, r, "Failed to append param type to netlink message: %m");;

        *set_needed = true;
        return 0;
}

static int devlink_param_genl_process_bool(
                Devlink *devlink,
                sd_netlink_message *message,
                sd_netlink_message *req,
                bool *set_needed) {
        DevlinkParam *param = DEVLINK_PARAM(devlink);
        bool val, current_val;
        int r;

        r = parse_boolean(param->value);
        if (r < 0)
                return log_devlink_debug_errno(devlink, r, "Failed to parse boolean param value: %m");
        val = r;

        current_val = sd_netlink_message_has_flag(message, DEVLINK_ATTR_PARAM_VALUE_DATA);

        log_devlink_debug(devlink, "Current value \"%s\", desired value \"%s\".", true_false(current_val), true_false(val));

        if (current_val == val)
                return 0;

        log_devlink_info(devlink, "Value to be set: \"%s\".", true_false(val));

        *set_needed = true;
        if (!val)
                return 0;

        r = sd_netlink_message_append_flag(req, DEVLINK_ATTR_PARAM_VALUE_DATA);
        if (r < 0)
                return log_devlink_debug_errno(devlink, r, "Failed to append param type to netlink message: %m");;

        return 0;
}

static int devlink_param_genl_process_append_type_value(
                Devlink *devlink,
                sd_netlink_message *message,
                sd_netlink_message *req,
                bool *set_needed,
                uint8_t type) {
        switch (type) {
        case DEVLINK_PARAM_TYPE_U8:
                return devlink_param_genl_process_u8(devlink, message, req, set_needed);
        case DEVLINK_PARAM_TYPE_U16:
                return devlink_param_genl_process_u16(devlink, message, req, set_needed);
        case DEVLINK_PARAM_TYPE_U32:
                return devlink_param_genl_process_u32(devlink, message, req, set_needed);
        case DEVLINK_PARAM_TYPE_STRING:
                return devlink_param_genl_process_string(devlink, message, req, set_needed);
        case DEVLINK_PARAM_TYPE_FLAG:
                return devlink_param_genl_process_bool(devlink, message, req, set_needed);
        default:
                return log_devlink_debug_errno(devlink, SYNTHETIC_ERRNO(EINVAL),
                                               "devlink netlink: Unknown param type: %m");;
        }

        return 0;
}

static int devlink_param_genl_set(
                Devlink *devlink,
                DevlinkKey *lookup_key,
                sd_netlink_message *message,
                uint8_t set_cmd,
                DevlinkParam *param,
                uint8_t type,
                uint8_t cmode) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *rep = NULL;
        bool set_needed = false;
        int r;

        r = devlink_genl_message_new(devlink, set_cmd, &req);
        if (r < 0)
                return log_devlink_debug_errno(devlink, r, "Failed to create netlink message: %m");;

        r = devlink_key_genl_append(req, lookup_key);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u8(req, DEVLINK_ATTR_PARAM_TYPE, type);
        if (r < 0)
                return log_devlink_debug_errno(devlink, r, "Failed to append param type to netlink message: %m");;

        r = sd_netlink_message_append_u8(req, DEVLINK_ATTR_PARAM_VALUE_CMODE, cmode);
        if (r < 0)
                return log_devlink_debug_errno(devlink, r, "Failed to append param cmode to netlink message: %m");;

        r = devlink_param_genl_process_append_type_value(devlink, message, req, &set_needed, type);
        if (r < 0)
                return r;

        /* The current value is the same as the desired one, just quit. */
        if (!set_needed) {
                log_devlink_debug(devlink, "Value already set, skipping.");
                return 0;
        }

        r = sd_netlink_call(devlink->manager->genl, req, 0, &rep);
        if (r < 0)
                return log_devlink_error_errno(devlink, r, "Could not send set message: %m");

        r = sd_netlink_message_get_errno(rep);
        if (r < 0)
                return log_devlink_error_errno(devlink, r, "Failed to set param: %m");

        log_devlink_info(devlink, "Set success");

        if (cmode == DEVLINK_PARAM_CMODE_DRIVERINIT || cmode == DEVLINK_PARAM_CMODE_PERMANENT)
                devlink_reload_queue(devlink->manager, &lookup_key->match);

        return 0;
}

static int __devlink_param_genl_cmd_new_msg_process(
                Devlink *devlink,
                DevlinkKey *lookup_key,
                sd_netlink_message *message,
                uint8_t set_cmd) {
        DevlinkParam *param = DEVLINK_PARAM(devlink);
        uint8_t type;
        int r;

        r = sd_netlink_message_enter_container(message, DEVLINK_ATTR_PARAM);
        if (r < 0)
                return log_devlink_debug_errno(devlink, r, "Netlink message without param nest: %m");

        r = sd_netlink_message_read_u8(message, DEVLINK_ATTR_PARAM_TYPE, &type);
        if (r < 0)
                return log_devlink_debug_errno(devlink, r, "Netlink message without param type value: %m");

        r = sd_netlink_message_enter_container(message, DEVLINK_ATTR_PARAM_VALUES_LIST);
        if (r < 0)
                return log_devlink_debug_errno(devlink, r, "devlink netlink: Message without param values list nest: %m");

        size_t count;
        (void) sd_netlink_message_get_attributes_count(message, DEVLINK_ATTR_PARAM_VALUE, &count);

        for (unsigned i = 0; i < count; i++) {
                uint8_t cmode;

                r = sd_netlink_message_enter_container_indexed(message, DEVLINK_ATTR_PARAM_VALUE, i);
                if (r < 0)
                        return log_debug_errno(r, "Netlink message without valid param values list item nest: %m");

                r = sd_netlink_message_read_u8(message, DEVLINK_ATTR_PARAM_VALUE_CMODE, &cmode);
                if (r < 0)
                        return log_devlink_debug_errno(devlink, r, "devlink netlink: Message without param cmode value: %m");

                r = devlink_param_genl_set(devlink, lookup_key, message, set_cmd, param, type, cmode);
                if (r < 0)
                        return r;

                (void) sd_netlink_message_exit_container(message);
        }

        (void) sd_netlink_message_exit_container(message);
        (void) sd_netlink_message_exit_container(message);

        return DEVLINK_MONITOR_COMMAND_RETVAL_OK;
}

static int devlink_param_genl_cmd_new_msg_process(
                Devlink *devlink,
                DevlinkKey *lookup_key,
                sd_netlink_message *message) {
        return __devlink_param_genl_cmd_new_msg_process(devlink, lookup_key, message, DEVLINK_CMD_PARAM_SET);
}

static int devlink_port_param_genl_cmd_new_msg_process(
                Devlink *devlink,
                DevlinkKey *lookup_key,
                sd_netlink_message *message) {
        return __devlink_param_genl_cmd_new_msg_process(devlink, lookup_key, message, DEVLINK_CMD_PORT_PARAM_SET);
}

static const DevlinkMatchSet devlink_param_matchsets[] = {
        DEVLINK_MATCH_BIT_PORT_IFNAME | DEVLINK_MATCH_BIT_COMMON_NAME,
        DEVLINK_MATCH_BIT_DEV | DEVLINK_MATCH_BIT_COMMON_INDEX | DEVLINK_MATCH_BIT_PORT_SPLIT | DEVLINK_MATCH_BIT_COMMON_NAME,
        DEVLINK_MATCH_BIT_DEV | DEVLINK_MATCH_BIT_COMMON_NAME,
        0,
};

static const DevlinkMonitorCommand devlink_param_commands[] = {
        { DEVLINK_CMD_PARAM_GET, NULL, true, DEVLINK_CMD_PARAM_NEW }, /* Buggy kernel sends "get" cmd for do/dump reply of "get" cmd */
        { DEVLINK_CMD_PARAM_NEW, devlink_param_genl_cmd_new_msg_process },
        { DEVLINK_CMD_PORT_PARAM_GET, NULL, true, DEVLINK_CMD_PORT_PARAM_NEW }, /* Buggy kernel sends "get" cmd for do/dump reply of "get" cmd */
        { DEVLINK_CMD_PORT_PARAM_NEW, devlink_port_param_genl_cmd_new_msg_process },
};

const DevlinkVTable devlink_param_vtable = {
        .object_size = sizeof(DevlinkParam),
        .sections = DEVLINK_COMMON_SECTIONS "Param\0",
        .matchsets = devlink_param_matchsets,
        .done = devlink_param_done,
        .config_verify = devlink_param_config_verify,
        .genl_monitor_cmds = devlink_param_commands,
        .genl_monitor_cmds_count = ELEMENTSOF(devlink_param_commands),
};
