/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "hash-funcs.h"
#include "list.h"
#include "macro.h"
#include "string-util.h"

#include "devlinkd-manager.h"
#include "devlink.h"
#include "devlink-key.h"
#include "devlink-match.h"
#include "devlink-port-cache.h"
#include "devlink-ifname-tracker.h"

typedef struct DevlinkIfnameTrackerItem {
        Manager *manager;
        unsigned n_ref;
        char *ifname;
        uint64_t ifindex;
        bool in_hashmap_by_ifname;
        bool in_hashmap_by_ifindex;
        LIST_HEAD(Devlink, ifname_tracker);
} DevlinkIfnameTrackerItem;

static DevlinkIfnameTrackerItem *devlink_ifname_tracker_item_free(DevlinkIfnameTrackerItem *item) {
        assert(item);
        assert(item->ifname_tracker == NULL);

        if (item->in_hashmap_by_ifindex)
                hashmap_remove(item->manager->ifname_tracker_by_ifindex, &item->ifindex);

        if (item->in_hashmap_by_ifname)
                hashmap_remove(item->manager->ifname_tracker_by_ifname, item->ifname);

        log_debug("ifname tracker: \"%s\" removed\n", item->ifname);
        item->ifname = mfree(item->ifname);

        return mfree(item);
}

DEFINE_PRIVATE_TRIVIAL_REF_UNREF_FUNC(DevlinkIfnameTrackerItem, devlink_ifname_tracker_item, devlink_ifname_tracker_item_free);
DEFINE_TRIVIAL_CLEANUP_FUNC(DevlinkIfnameTrackerItem *, devlink_ifname_tracker_item_unref);

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
        devlink_ifname_tracker_item_by_ifname_hash_ops,
        char,
        string_hash_func,
        string_compare_func,
        DevlinkIfnameTrackerItem,
        devlink_ifname_tracker_item_unref);

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
        devlink_ifname_tracker_item_by_ifindex_hash_ops,
        uint64_t,
        uint64_hash_func,
        uint64_compare_func,
        DevlinkIfnameTrackerItem,
        devlink_ifname_tracker_item_unref);

static DevlinkIfnameTrackerItem *devlink_ifname_tracker_item_alloc(Manager *m, const char *ifname) {
        _cleanup_(devlink_ifname_tracker_item_unrefp) DevlinkIfnameTrackerItem *item;
        int r;

        item = malloc0(sizeof(DevlinkIfnameTrackerItem));
        if (!item)
                return NULL;

        *item = (DevlinkIfnameTrackerItem) {
                .manager = m,
                .n_ref = 1,
        };

        item->ifname = strdup(ifname);
        if (!item->ifname)
                return NULL;

        r = hashmap_ensure_put(&m->ifname_tracker_by_ifname, &devlink_ifname_tracker_item_by_ifname_hash_ops, item->ifname, item);
        if (r < 0)
                return NULL;
        item->in_hashmap_by_ifname = true;
        log_debug("ifname tracker: \"%s\" added\n", ifname);

        return TAKE_PTR(item);
}

int devlink_ifname_tracker_add(Devlink *devlink) {
        DevlinkIfnameTrackerItem *item;
        char *ifname;

        assert(devlink);

        if (!(devlink->key.matchset & DEVLINK_MATCH_BIT_PORT_IFNAME))
                return 0;

        ifname = devlink->key.match.port.ifname;
        item = hashmap_get(devlink->manager->ifname_tracker_by_ifname, ifname);
        if (!item) {
                item = devlink_ifname_tracker_item_alloc(devlink->manager, ifname);
                if (!item)
                        return -ENOMEM;
        }

        LIST_APPEND(ifname_tracker, item->ifname_tracker, devlink);
        devlink->in_ifname_tracker = true;
        devlink_ifname_tracker_item_ref(item);

        return 0;
}

void devlink_ifname_tracker_del(Devlink *devlink) {
        DevlinkIfnameTrackerItem *item;
        char *ifname;

        assert(devlink);

        if (!(devlink->key.matchset & DEVLINK_MATCH_BIT_PORT_IFNAME))
                return;

        ifname = devlink->key.match.port.ifname;
        item = hashmap_get(devlink->manager->ifname_tracker_by_ifname, ifname);
        assert(item);

        LIST_REMOVE(ifname_tracker, item->ifname_tracker, devlink);
        devlink_ifname_tracker_item_unref(item);
}

int devlink_ifname_tracker_query(Manager *m, uint64_t ifindex, char **ifname) {
        DevlinkIfnameTrackerItem *item;
        int r;

        log_debug("ifname tracker: query ifindex %" PRIu64 "\n", ifindex);
        item = hashmap_get(m->ifname_tracker_by_ifindex, &ifindex);
        if (!item)
                return -ENOENT;
        r = free_and_strdup(ifname, item->ifname);
        if (r < 0)
                return r;
        return 0;
}

static int devlink_ifname_tracker_enumerate_key_get(Manager *m, DevlinkKey *key, Devlink *devlink, uint64_t ifindex) {
        int r;

        devlink_key_init(key, devlink->key.kind);
        r = devlink_port_cache_query_by_ifindex(m, ifindex, key);
        if (r < 0)
                return r;
        devlink_key_copy_subkey(key, &devlink->key,
                                devlink->key.matchset & ~DEVLINK_MATCH_BIT_PORT_IFNAME);
        return 0;
}

static int devlink_ifname_tracker_ifindex_update_one(Manager *m, uint64_t ifindex, const char *ifname, const char **found_ifname) {
        DevlinkIfnameTrackerItem *item, *orig_item;
        int r;

        item = hashmap_get(m->ifname_tracker_by_ifname, ifname);
        if (item && *found_ifname) {
                log_warning("Multiple netdevice names for the same port match is not supported in config, \"%s\" will be ignored (\"%s\" is already tracked)\n", ifname, *found_ifname);
                return 0;
        } else if (!item) {
                return 0;
        }

        *found_ifname = item->ifname;

        orig_item = hashmap_get(m->ifname_tracker_by_ifindex, &ifindex);
        if (item == orig_item)
                return 0;

        item->ifindex = ifindex;
        r = hashmap_ensure_put(&m->ifname_tracker_by_ifindex, &devlink_ifname_tracker_item_by_ifindex_hash_ops, &item->ifindex, item);
        if (r < 0)
                return r;
        log_debug("ifname tracker: \"%s\" updated to ifindex \"%" PRIu64 "\"\n", item->ifname, ifindex);

        LIST_FOREACH(ifname_tracker, devlink, item->ifname_tracker) {
                DevlinkKey key = {};

                r = devlink_ifname_tracker_enumerate_key_get(m, &key, devlink, ifindex);
                if (r < 0)
                        continue;
                manager_enumerate_by_key(m, &key);
        }
        return 0;
}

int devlink_ifname_tracker_ifindex_update(Manager *m, uint64_t ifindex, sd_netlink_message *message) {
        const char *found_ifname = NULL;
        const char *ifname;
        int r;

        r = sd_netlink_message_read_string(message, IFLA_IFNAME, &ifname);
        if (!r) {
                r = devlink_ifname_tracker_ifindex_update_one(m, ifindex, ifname, &found_ifname);
                if (r < 0)
                        return r;
        }

        r = sd_netlink_message_enter_container(message, IFLA_PROP_LIST);
        if (r < 0)
                return 0;

        size_t count;
        (void) sd_netlink_message_get_attributes_count(message, IFLA_ALT_IFNAME, &count);

        for (unsigned i = 0; i < count; i++) {
                r = sd_netlink_message_read_string_indexed(message, IFLA_ALT_IFNAME, &ifname, i);
                if (!r) {
                        r = devlink_ifname_tracker_ifindex_update_one(m, ifindex, ifname, &found_ifname);
                        if (r < 0)
                                return r;
                }
        }

        (void) sd_netlink_message_exit_container(message);

        return 0;
}

void devlink_ifname_tracker_ifindex_remove(Manager *m, uint64_t ifindex) {
        hashmap_remove(m->ifname_tracker_by_ifindex, &ifindex);
}
