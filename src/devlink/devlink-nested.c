/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/devlink.h>

#include "sd-netlink.h"

#include "devlink.h"
#include "devlink-key.h"
#include "devlink-nested.h"

DevlinkMatch *devlink_nested_in_match(Manager *m, DevlinkMatch *match) {
        DevlinkKey key = {};

        devlink_key_init(&key, DEVLINK_KIND_NESTED);
        devlink_key_copy_from_match(&key, match, DEVLINK_MATCH_BIT_DEV);

        Devlink *devlink = devlink_get(m, &key);
        if (!devlink)
                return NULL;

        DevlinkNested *nested = DEVLINK_NESTED(devlink);
        if (!nested->nested_in)
                return NULL;

        return &nested->nested_in->key.match;
}

static void devlink_nested_in_update(Devlink *devlink, Devlink *nested_in_devlink) {
        DevlinkNested *nested = DEVLINK_NESTED(devlink);

        if (nested->nested_in == nested_in_devlink)
                return;
        devlink_unref(nested->nested_in);
        nested->nested_in = nested_in_devlink;
        devlink_ref(nested->nested_in);
        log_devlink_debug(devlink, "Nested in devlink updated:");
        log_devlink_debug(nested_in_devlink, "This is the new nested in devlink");
}

static int devlink_nested_genl_cmd_new_msg_process(
                Devlink *devlink,
                DevlinkKey *lookup_key,
                sd_netlink_message *message) {
        Devlink *nested_devlink;
        size_t count;
        int r;

        (void) sd_netlink_message_get_attributes_count(message, DEVLINK_ATTR_NESTED_DEVLINK, &count);

        for (unsigned i = 0; i < count; i++) {
                r = sd_netlink_message_enter_container_indexed(message, DEVLINK_ATTR_NESTED_DEVLINK, i);
                if (r < 0)
                        return log_debug_errno(r, "Netlink message without valid nested devlink nest: %m");

                r = sd_netlink_message_read_s32(message, DEVLINK_ATTR_NETNS_ID, NULL);
                if (!r) {
                        (void) sd_netlink_message_exit_container(message);
                        continue;
                }

                DevlinkKey key = {};

                devlink_key_init(&key, DEVLINK_KIND_NESTED);
                devlink_match_genl_read(message, devlink->manager, &key.match, &key.matchset);

                (void) sd_netlink_message_exit_container(message);

                nested_devlink = devlink_get_may_create_filtered(devlink->manager, &key, DEVLINK_MATCH_BIT_DEV);

                devlink_key_fini(&key);

                if (!nested_devlink)
                        continue;

                devlink_nested_in_update(nested_devlink, devlink);
        }

        return DEVLINK_MONITOR_COMMAND_RETVAL_OK;
}

static int devlink_nested_genl_cmd_del_msg_process(
                Devlink *devlink,
                DevlinkKey *lookup_key,
                sd_netlink_message *message) {
        DevlinkNested *nested = DEVLINK_NESTED(devlink);

        devlink_unref(nested->nested_in);
        return DEVLINK_MONITOR_COMMAND_RETVAL_DELETE;
}

static const DevlinkMatchSet devlink_nested_matchsets[] = {
        DEVLINK_MATCH_BIT_DEV,
        0,
};

static const DevlinkMonitorCommand devlink_nested_commands[] = {
        { DEVLINK_CMD_NEW, devlink_nested_genl_cmd_new_msg_process },
        { DEVLINK_CMD_DEL, devlink_nested_genl_cmd_del_msg_process },
};

const DevlinkVTable devlink_nested_vtable = {
        .object_size = sizeof(DevlinkNested),
        .matchsets = devlink_nested_matchsets,
        .alloc_on_demand = true,
        .genl_monitor_cmds = devlink_nested_commands,
        .genl_monitor_cmds_count = ELEMENTSOF(devlink_nested_commands),
};
