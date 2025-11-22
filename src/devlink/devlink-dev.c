/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/devlink.h>

#include "sd-netlink.h"

#include "devlink-util.h"
#include "conf-parser.h"

#include "devlink-dev.h"

DEFINE_CONFIG_PARSE_ENUM(config_parse_devlink_dev_eswitch_mode, devlink_dev_eswitch_mode, DevlinkDevESwitchMode);

static void devlink_dev_init(Devlink *devlink) {
        DevlinkDev *dev = DEVLINK_DEV(devlink);

        dev->eswitch_mode = _DEVLINK_DEV_ESWITCH_MODE_INVALID;
}

static int devlink_dev_genl_eswitch_set(
                Devlink *devlink,
                DevlinkKey *lookup_key,
                DevlinkDev *dev) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *rep = NULL;
        int r;

        r = devlink_genl_message_new(devlink, DEVLINK_CMD_ESWITCH_SET, &req);
        if (r < 0)
                return log_devlink_debug_errno(devlink, r, "Failed to create netlink message: %m");;

        r = devlink_key_genl_append(req, lookup_key);
        if (r < 0)
                return r;

        log_devlink_info(devlink, "Eswitch mode to be set: \"%s\".", devlink_dev_eswitch_mode_to_string(dev->eswitch_mode));

        r = sd_netlink_message_append_u16(req, DEVLINK_ATTR_ESWITCH_MODE, dev->eswitch_mode);
        if (r < 0)
                return log_devlink_debug_errno(devlink, r, "Failed to append eswitch mode to netlink message: %m");;

        r = sd_netlink_call(devlink->manager->genl, req, 0, &rep);
        if (r < 0)
                return log_devlink_error_errno(devlink, r, "Could not send eswitch set message: %m");

        r = sd_netlink_message_get_errno(rep);
        if (r < 0)
                return log_devlink_error_errno(devlink, r, "Eswitch could not be set: %m");

        log_devlink_info(devlink, "Eswitch set success");

        return 0;
}

static int devlink_dev_genl_eswitch_get(
                Devlink *devlink,
                DevlinkKey *lookup_key,
                DevlinkDev *dev,
                uint16_t *eswitch_mode) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *rep = NULL;
        int r;

        r = devlink_genl_message_new(devlink, DEVLINK_CMD_ESWITCH_GET, &req);
        if (r < 0)
                return log_devlink_debug_errno(devlink, r, "Failed to create netlink message: %m");;

        r = devlink_key_genl_append(req, lookup_key);
        if (r < 0)
                return r;

        r = sd_netlink_call(devlink->manager->genl, req, 0, &rep);
        if (r < 0)
                return log_devlink_error_errno(devlink, r, "Could not send eswitch get message: %m");

        r = sd_netlink_message_get_errno(rep);
        if (r < 0)
                return log_devlink_error_errno(devlink, r, "Eswitch could not be get: %m");

        r = sd_netlink_message_read_u16(rep, DEVLINK_ATTR_ESWITCH_MODE, eswitch_mode);
        if (r < 0)
                return log_devlink_debug_errno(devlink, r, "Netlink message without eswitch mode value: %m");

        return 0;
}

static int devlink_dev_genl_cmd_new_msg_process(
                Devlink *devlink,
                DevlinkKey *lookup_key,
                sd_netlink_message *message) {
        DevlinkDev *dev = DEVLINK_DEV(devlink);
        uint16_t current_eswitch_mode;
        int r;

        if (dev->eswitch_mode != _DEVLINK_DEV_ESWITCH_MODE_INVALID) {
                r = devlink_dev_genl_eswitch_get(devlink, lookup_key, dev, &current_eswitch_mode);
                if (r < 0)
                        return r;
                if ((uint16_t) dev->eswitch_mode != current_eswitch_mode) {
                        r = devlink_dev_genl_eswitch_set(devlink, lookup_key, dev);
                        if (r < 0)
                                return r;
                } else {
                        log_devlink_debug(devlink, "Eswitch mode set skipped, already set");
                }
        }

        return DEVLINK_MONITOR_COMMAND_RETVAL_OK;
}

static const DevlinkMatchSet devlink_dev_matchsets[] = {
        DEVLINK_MATCH_BIT_DEV,
        0,
};

static const DevlinkMonitorCommand devlink_dev_commands[] = {
        { DEVLINK_CMD_GET, NULL, true },
        { DEVLINK_CMD_NEW, devlink_dev_genl_cmd_new_msg_process },
};

const DevlinkVTable devlink_dev_vtable = {
        .object_size = sizeof(DevlinkDev),
        .sections = DEVLINK_COMMON_SECTIONS "Dev\0",
        .matchsets = devlink_dev_matchsets,
        .init = devlink_dev_init,
        .genl_monitor_cmds = devlink_dev_commands,
        .genl_monitor_cmds_count = ELEMENTSOF(devlink_dev_commands),
};
