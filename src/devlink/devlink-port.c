/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/devlink.h>

#include "devlink.h"
#include "devlink-port.h"

static void devlink_port_init(Devlink *devlink) {
        DevlinkPort *port = DEVLINK_PORT(devlink);

        port->split_count = _DEVLINK_PORT_SPLIT_COUNT_INVALID;
}

static int devlink_port_genl_split(
                Devlink *devlink,
                DevlinkKey *lookup_key,
                DevlinkPort *port) {
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *req = NULL;
        _cleanup_(sd_netlink_message_unrefp) sd_netlink_message *rep = NULL;
        int r;

        r = devlink_genl_message_new(devlink, DEVLINK_CMD_PORT_SPLIT, &req);
        if (r < 0)
                return log_devlink_debug_errno(devlink, r, "Failed to create netlink message: %m");;

        r = devlink_key_genl_append(req, lookup_key);
        if (r < 0)
                return r;

        r = sd_netlink_message_append_u32(req, DEVLINK_ATTR_PORT_SPLIT_COUNT, port->split_count);
        if (r < 0)
                return log_devlink_debug_errno(devlink, r, "Failed to append split count to netlink message: %m");;

        r = sd_netlink_call(devlink->manager->genl, req, 0, &rep);
        if (r < 0)
                return log_devlink_error_errno(devlink, r, "Could not send port split message: %m");

        r = sd_netlink_message_get_errno(rep);
        if (r < 0)
                return log_devlink_error_errno(devlink, r, "Port could not be split: %m");

        log_devlink_info(devlink, "Split success");

        devlink_expected_removal_set(devlink);

        return 0;
}

static int devlink_port_genl_cmd_new_msg_process(
                Devlink *devlink,
                DevlinkKey *lookup_key,
                sd_netlink_message *message) {
        DevlinkPort *port = DEVLINK_PORT(devlink);
        int r;

        if (devlink->expected_removal)
                return DEVLINK_MONITOR_COMMAND_RETVAL_OK;

        if (port->split_count != _DEVLINK_PORT_SPLIT_COUNT_INVALID) {
                r = devlink_port_genl_split(devlink, lookup_key, port);
                if (r < 0)
                        return r;
        }
        return DEVLINK_MONITOR_COMMAND_RETVAL_OK;
}

static int devlink_port_genl_cmd_del_msg_process(
                Devlink *devlink,
                DevlinkKey *lookup_key,
                sd_netlink_message *message) {
        devlink_expected_removal_clear(devlink);
        return DEVLINK_MONITOR_COMMAND_RETVAL_OK;
}

static const DevlinkMatchSet devlink_port_matchsets[] = {
        DEVLINK_MATCH_BIT_PORT_IFNAME,
        DEVLINK_MATCH_BIT_DEV | DEVLINK_MATCH_BIT_COMMON_INDEX | DEVLINK_MATCH_BIT_PORT_SPLIT,
        0,
};

static const DevlinkMonitorCommand devlink_port_commands[] = {
        { DEVLINK_CMD_PORT_GET, NULL, true, DEVLINK_CMD_PORT_NEW },
        { DEVLINK_CMD_PORT_NEW, devlink_port_genl_cmd_new_msg_process },
        { DEVLINK_CMD_PORT_DEL, devlink_port_genl_cmd_del_msg_process },
};

const DevlinkVTable devlink_port_vtable = {
        .object_size = sizeof(DevlinkPort),
        .sections = DEVLINK_COMMON_SECTIONS "Port\0",
        .matchsets = devlink_port_matchsets,
        .init = devlink_port_init,
        .genl_monitor_cmds = devlink_port_commands,
        .genl_monitor_cmds_count = ELEMENTSOF(devlink_port_commands),
};
