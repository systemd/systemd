/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "sd-device.h"

#include "MurmurHash2.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "set.h"
#include "socket-util.h"

#define DEVICE_ENUMERATE_MAX_DEPTH 256
#define UDEV_MONITOR_MAGIC 0xfeedcafe

typedef enum MatchInitializedType {
        MATCH_INITIALIZED_NO,     /* only devices without a db entry */
        MATCH_INITIALIZED_YES,    /* only devices with a db entry */
        MATCH_INITIALIZED_ALL,    /* all devices */
        MATCH_INITIALIZED_COMPAT, /* only devices that have no devnode/ifindex or have a db entry */
        _MATCH_INITIALIZED_MAX,
        _MATCH_INITIALIZED_INVALID = -EINVAL,
} MatchInitializedType;

typedef enum DeviceEnumerationType {
        DEVICE_ENUMERATION_TYPE_DEVICES,
        DEVICE_ENUMERATION_TYPE_SUBSYSTEMS,
        DEVICE_ENUMERATION_TYPE_ALL,
        _DEVICE_ENUMERATION_TYPE_MAX,
        _DEVICE_ENUMERATION_TYPE_INVALID = -EINVAL,
} DeviceEnumerationType;

struct sd_device_enumerator {
        unsigned n_ref;

        DeviceEnumerationType type;
        Hashmap *devices_by_syspath;
        sd_device **devices;
        size_t n_devices, current_device_index;
        bool scan_uptodate;
        bool sorted;

        char **prioritized_subsystems;
        Set *match_subsystem;
        Set *nomatch_subsystem;
        Hashmap *match_sysattr;
        Hashmap *nomatch_sysattr;
        Hashmap *match_property;
        Set *match_sysname;
        Set *nomatch_sysname;
        Set *match_tag;
        Set *match_parent;
        MatchInitializedType match_initialized;
};

struct sd_device_monitor {
        unsigned n_ref;

        int sock;
        union sockaddr_union snl;
        union sockaddr_union snl_trusted_sender;
        bool bound;

        Hashmap *subsystem_filter;
        Set *tag_filter;
        Hashmap *match_sysattr_filter;
        Hashmap *nomatch_sysattr_filter;
        Set *match_parent_filter;
        Set *nomatch_parent_filter;
        bool filter_uptodate;

        sd_event *event;
        sd_event_source *event_source;
        sd_device_monitor_handler_t callback;
        void *userdata;
};

typedef struct monitor_netlink_header {
        /* "libudev" prefix to distinguish libudev and kernel messages */
        char prefix[8];
        /* Magic to protect against daemon <-> Library message format mismatch
         * Used in the kernel from socket filter rules; needs to be stored in network order */
        unsigned magic;
        /* Total length of header structure known to the sender */
        unsigned header_size;
        /* Properties string buffer */
        unsigned properties_off;
        unsigned properties_len;
        /* Hashes of primary device properties strings, to let libudev subscribers
         * use in-kernel socket filters; values need to be stored in network order */
        unsigned filter_subsystem_hash;
        unsigned filter_devtype_hash;
        unsigned filter_tag_bloom_hi;
        unsigned filter_tag_bloom_lo;
} monitor_netlink_header;

typedef enum MonitorNetlinkGroup {
        MONITOR_GROUP_NONE,
        MONITOR_GROUP_KERNEL,
        MONITOR_GROUP_UDEV,
        _MONITOR_NETLINK_GROUP_MAX,
        _MONITOR_NETLINK_GROUP_INVALID = -EINVAL,
} MonitorNetlinkGroup;

void device_enumerator_unref_devices(sd_device_enumerator *enumerator);
int device_enumerator_scan_devices(sd_device_enumerator *enumerator);
int device_enumerator_scan_subsystems(sd_device_enumerator *enumerator);
int device_enumerator_scan_devices_and_subsystems(sd_device_enumerator *enumerator);
int device_enumerator_sort_devices(sd_device_enumerator *enumerator);
int device_enumerator_add_device(sd_device_enumerator *enumerator, sd_device *device);
int device_enumerator_add_parent_devices(sd_device_enumerator *enumerator, sd_device *device);
int device_enumerator_add_match_is_initialized(sd_device_enumerator *enumerator, MatchInitializedType type);
int device_enumerator_add_match_parent_incremental(sd_device_enumerator *enumerator, sd_device *parent);
int device_enumerator_add_prioritized_subsystem(sd_device_enumerator *enumerator, const char *subsystem);
sd_device* device_enumerator_get_first(sd_device_enumerator *enumerator);
sd_device* device_enumerator_get_next(sd_device_enumerator *enumerator);
sd_device** device_enumerator_get_devices(sd_device_enumerator *enumerator, size_t *ret_n_devices);
int enumerator_scan_devices_tags(sd_device_enumerator *enumerator);

#define FOREACH_DEVICE_AND_SUBSYSTEM(enumerator, device)       \
        for (device = device_enumerator_get_first(enumerator); \
             device;                                           \
             device = device_enumerator_get_next(enumerator))

int device_monitor_new_full(sd_device_monitor **ret, MonitorNetlinkGroup group, int fd);
int device_monitor_disconnect(sd_device_monitor *m);
int device_monitor_allow_unicast_sender(sd_device_monitor *m, sd_device_monitor *sender);
int device_monitor_enable_receiving(sd_device_monitor *m);
int device_monitor_get_fd(sd_device_monitor *m);
int device_monitor_send_device(sd_device_monitor *m, sd_device_monitor *destination, sd_device *device);
int device_monitor_receive_device(sd_device_monitor *m, sd_device **ret);

static inline uint32_t string_hash32(const char *str) {
        return MurmurHash2(str, strlen(str), 0);
}

/* Get a bunch of bit numbers out of the hash, and set the bits in our bit field */
static inline uint64_t string_bloom64(const char *str) {
        uint64_t bits = 0;
        uint32_t hash = string_hash32(str);

        bits |= UINT64_C(1) << (hash & 63);
        bits |= UINT64_C(1) << ((hash >> 6) & 63);
        bits |= UINT64_C(1) << ((hash >> 12) & 63);
        bits |= UINT64_C(1) << ((hash >> 18) & 63);
        return bits;
}
