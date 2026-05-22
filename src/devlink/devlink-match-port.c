/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/devlink.h>

#include "sd-netlink.h"
#include "log.h"
#include "macro.h"
#include "siphash24.h"
#include "conf-parser.h"

#include "devlink-match.h"
#include "devlink-match-port.h"
#include "devlink-port-cache.h"
#include "devlink-ifname-tracker.h"

static int devlink_match_port_index_genl_read(
                sd_netlink_message *message,
                Manager *m,
                DevlinkMatch *match) {
        DevlinkMatchCommon *common = &match->common;
        int r;

        if (common->index_valid)
                return -ENODATA;

        r = sd_netlink_message_read_u32(message, DEVLINK_ATTR_PORT_INDEX, &common->index);
        if (r < 0)
                return r;
        common->index_valid = true;

        return 0;
}

static int devlink_match_port_genl_append(sd_netlink_message *message, const DevlinkMatch *match) {
        const DevlinkMatchCommon *common = &match->common;
        int r;

        assert(common->index_valid);

        r = sd_netlink_message_append_u32(message, DEVLINK_ATTR_PORT_INDEX, common->index);
        if (r < 0)
                return log_debug_errno(r, "Failed to append port index to netlink message: %m");
        return 0;
}

const DevlinkMatchVTable devlink_match_port_index_vtable = {
        .bit = DEVLINK_MATCH_BIT_COMMON_INDEX,
        .check = devlink_match_common_index_check,
        .log_prefix = devlink_match_common_index_log_prefix,
        .hash_func = devlink_match_common_index_hash_func,
        .compare_func = devlink_match_common_index_compare_func,
        .copy_func = devlink_match_common_index_copy_func,
        .duplicate_func = devlink_match_common_index_duplicate_func,
        .genl_read = devlink_match_port_index_genl_read,
        .genl_append = devlink_match_port_genl_append,
};

int config_parse_devlink_port_split(CONFIG_PARSER_ARGUMENTS) {
        DevlinkMatchPort *port = data;
        int r;

        r = config_parse_bool(unit, filename, line, section, section_line, lvalue, ltype,
                              rvalue, &port->split, userdata);
        if (r < 0)
                return r;
        port->split_explicit = true;
        return 0;
}

static bool devlink_match_port_split_check(const DevlinkMatch *match, bool explicit) {
        const DevlinkMatchPort *port = &match->port;

        return explicit && !port->split_explicit ? false : true;
}

static void devlink_match_port_split_log_prefix(char **buf, int *len, const DevlinkMatch *match) {
        const DevlinkMatchPort *port = &match->port;

        BUFFER_APPEND(*buf, *len, "split %s", port->split ? "true" : "false");
}

static void devlink_match_port_split_hash_func(const DevlinkMatch *match, struct siphash *state) {
        const DevlinkMatchPort *port = &match->port;

        siphash24_compress_boolean(port->split, state);
}

static int devlink_match_port_split_compare_func(const DevlinkMatch *x, const DevlinkMatch *y) {
        const DevlinkMatchPort *xport = &x->port;
        const DevlinkMatchPort *yport = &y->port;

        return CMP(xport->split, yport->split);
}

static void devlink_match_port_split_copy_func(DevlinkMatch *dst, const DevlinkMatch *src) {
        DevlinkMatchPort *dstport = &dst->port;
        const DevlinkMatchPort *srcport = &src->port;

        dstport->split = srcport->split;
}

static int devlink_match_port_split_duplicate_func(DevlinkMatch *dst, const DevlinkMatch *src) {
        devlink_match_port_split_copy_func(dst, src);
        return 0;
}

static int devlink_match_port_split_genl_read(
                sd_netlink_message *message,
                Manager *m,
                DevlinkMatch *match) {
        DevlinkMatchPort *port = &match->port;
        uint32_t split_group;
        int r;

        r = sd_netlink_message_read_u32(message, DEVLINK_ATTR_PORT_SPLIT_GROUP, &split_group);
        if (!r)
                port->split = true;

        return 0;
}

const DevlinkMatchVTable devlink_match_port_split_vtable = {
        .bit = DEVLINK_MATCH_BIT_PORT_SPLIT,
        .check = devlink_match_port_split_check,
        .log_prefix = devlink_match_port_split_log_prefix,
        .hash_func = devlink_match_port_split_hash_func,
        .compare_func = devlink_match_port_split_compare_func,
        .copy_func = devlink_match_port_split_copy_func,
        .duplicate_func = devlink_match_port_split_duplicate_func,
        .genl_read = devlink_match_port_split_genl_read,
};

static void devlink_match_port_ifname_free(DevlinkMatch *match) {
        DevlinkMatchPort *port = &match->port;

        port->ifname = mfree(port->ifname);
}

static bool devlink_match_port_ifname_check(const DevlinkMatch *match, bool explicit) {
        const DevlinkMatchPort *port = &match->port;

        if (!port->ifname) {
                log_debug("Match ifname not configured.");
                return false;
        }
        return true;
}

static void devlink_match_port_ifname_log_prefix(char **buf, int *len, const DevlinkMatch *match) {
        const DevlinkMatchPort *port = &match->port;

        BUFFER_APPEND(*buf, *len, "ifname %s split %s", port->ifname, port->split ? "true" : "false");
}

static void devlink_match_port_ifname_hash_func(const DevlinkMatch *match, struct siphash *state) {
        const DevlinkMatchPort *port = &match->port;

        assert(port->ifname);

        string_hash_func(port->ifname, state);
}

static int devlink_match_port_ifname_compare_func(const DevlinkMatch *x, const DevlinkMatch *y) {
        const DevlinkMatchPort *xport = &x->port;
        const DevlinkMatchPort *yport = &y->port;

        assert(xport->ifname);
        assert(yport->ifname);

        return strcmp(xport->ifname, yport->ifname);
}

static int devlink_match_port_ifname_genl_read(
                sd_netlink_message *message,
                Manager *m,
                DevlinkMatch *match) {
        DevlinkMatchCommon *common = &match->common;
        DevlinkMatchPort *port = &match->port;
        DevlinkMatchDev *dev = &match->dev;
        uint64_t ifindex;
        int r;

        if (!dev->bus_name || !dev->dev_name || !common->index_valid || !m)
                return -EINVAL;

        /* Do not rely on ifname/ifindex contained in the message:
         * 1) Some messages, like param, do not contain these attributes at all.
         * 2) Port messages containe ifname but if ifname changes, message
         *    is not generated for this change.
         * 3) Alternative ifnames are not handled in devlink messages at all.
         * So instead, query the port cache for ifindex and then obtain ifname
         * from tracker that stores info coming in over RT Netlink.
         */

        r = devlink_port_cache_query_by_match(m, match, &ifindex);
        if (r < 0)
                return r;

        return devlink_ifname_tracker_query(m, ifindex, &port->ifname);
}

const DevlinkMatchVTable devlink_match_port_ifname_vtable = {
        .bit = DEVLINK_MATCH_BIT_PORT_IFNAME,
        .free = devlink_match_port_ifname_free,
        .check = devlink_match_port_ifname_check,
        .log_prefix = devlink_match_port_ifname_log_prefix,
        .hash_func = devlink_match_port_ifname_hash_func,
        .compare_func = devlink_match_port_ifname_compare_func,
        .genl_read = devlink_match_port_ifname_genl_read,
};
