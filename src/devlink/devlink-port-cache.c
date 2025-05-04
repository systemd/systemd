/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/devlink.h>

#include "sd-netlink.h"

#include "devlink.h"
#include "devlink-port-cache.h"

DEFINE_PRIVATE_HASH_OPS(
        devlink_port_cache_by_ifindex_hash_ops,
        uint64_t,
        uint64_hash_func,
        uint64_compare_func);

static int devlink_port_cache_genl_cmd_new_msg_process(
                Devlink *devlink,
                DevlinkKey *lookup_key,
                sd_netlink_message *message) {
        DevlinkPortCache *port_cache = DEVLINK_PORT_CACHE(devlink);
        Manager *m = devlink->manager;
        uint32_t ifindex;
        int r;

        r = sd_netlink_message_read_u32(message, DEVLINK_ATTR_PORT_NETDEV_IFINDEX, &ifindex);
        if (r < 0)
                /* Message does not contain ifindex, ignore gracefully. */
                return DEVLINK_MONITOR_COMMAND_RETVAL_OK;

        if (port_cache->ifindex != 0)
                hashmap_remove(m->port_cache_by_ifindex, &port_cache->ifindex);

        port_cache->ifindex = ifindex;

        r = hashmap_ensure_put(&m->port_cache_by_ifindex, &devlink_port_cache_by_ifindex_hash_ops, &port_cache->ifindex, devlink);
        if (r < 0)
                return r;
        if (r == 1)
                log_devlink_debug(devlink, "Added ifindex \"%" PRIu32 "\"", ifindex);

        return DEVLINK_MONITOR_COMMAND_RETVAL_OK;
}

static int devlink_port_cache_genl_cmd_del_msg_process(
                Devlink *devlink,
                DevlinkKey *lookup_key,
                sd_netlink_message *message) {
        DevlinkPortCache *port_cache = DEVLINK_PORT_CACHE(devlink);
        Manager *m = devlink->manager;

        hashmap_remove(m->port_cache_by_ifindex, &port_cache->ifindex);
        log_devlink_debug(devlink, "Removed ifindex \"%" PRIu64 "\"", port_cache->ifindex);
        return DEVLINK_MONITOR_COMMAND_RETVAL_DELETE;
}

static const DevlinkMatchSet devlink_port_cache_matchsets[] = {
        DEVLINK_MATCH_BIT_DEV | DEVLINK_MATCH_BIT_COMMON_INDEX,
        0,
};

static const DevlinkMonitorCommand devlink_port_cache_commands[] = {
        { .cmd = DEVLINK_CMD_PORT_NEW, .msg_process = devlink_port_cache_genl_cmd_new_msg_process },
        { .cmd = DEVLINK_CMD_PORT_DEL, .msg_process = devlink_port_cache_genl_cmd_del_msg_process },
};

const DevlinkVTable devlink_port_cache_vtable = {
        .object_size = sizeof(DevlinkPortCache),
        .matchsets = devlink_port_cache_matchsets,
        .alloc_on_demand = true,
        .genl_monitor_cmds = devlink_port_cache_commands,
        .genl_monitor_cmds_count = ELEMENTSOF(devlink_port_cache_commands),
};

int devlink_port_cache_query_by_match(Manager *m, DevlinkMatch *match, uint64_t *ifindex) {
        DevlinkKey key = {};

        assert(m);
        assert(match);
        assert(ifindex);

        devlink_key_init(&key, DEVLINK_KIND_PORT_CACHE);
        devlink_key_copy_from_match(&key, match, DEVLINK_MATCH_BIT_DEV | DEVLINK_MATCH_BIT_COMMON_INDEX);

        Devlink *devlink = devlink_get(m, &key);
        if (!devlink)
                return -ENOENT;

        DevlinkPortCache *port_cache = DEVLINK_PORT_CACHE(devlink);
        if (port_cache->ifindex == 0)
                return -ENODATA;

        *ifindex = port_cache->ifindex;

        return 0;
}

int devlink_port_cache_query_by_ifindex(Manager *m, uint64_t ifindex, DevlinkKey *key) {
        Devlink *devlink;

        log_debug("port cache: query ifindex %" PRIu64, ifindex);
        devlink = hashmap_get(m->port_cache_by_ifindex, &ifindex);
        if (!devlink)
                return -ENOENT;
        devlink_key_copy_subkey(key, &devlink->key, DEVLINK_MATCH_BIT_DEV | DEVLINK_MATCH_BIT_COMMON_INDEX);
        return 0;
}
