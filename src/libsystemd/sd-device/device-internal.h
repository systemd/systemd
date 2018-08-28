/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "sd-device.h"

#include "hashmap.h"
#include "set.h"

struct sd_device {
        unsigned n_ref;

        sd_device *parent;
        bool parent_set; /* no need to try to reload parent */

        OrderedHashmap *properties;
        Iterator properties_iterator;
        uint64_t properties_generation; /* changes whenever the properties are changed */
        uint64_t properties_iterator_generation; /* generation when iteration was started */

        /* the subset of the properties that should be written to the db */
        OrderedHashmap *properties_db;

        Hashmap *sysattr_values; /* cached sysattr values */

        Set *sysattrs; /* names of sysattrs */
        Iterator sysattrs_iterator;
        bool sysattrs_read; /* don't try to re-read sysattrs once read */

        Set *tags;
        Iterator tags_iterator;
        uint64_t tags_generation; /* changes whenever the tags are changed */
        uint64_t tags_iterator_generation; /* generation when iteration was started */
        bool property_tags_outdated; /* need to update TAGS= property */

        Set *devlinks;
        Iterator devlinks_iterator;
        uint64_t devlinks_generation; /* changes whenever the devlinks are changed */
        uint64_t devlinks_iterator_generation; /* generation when iteration was started */
        bool property_devlinks_outdated; /* need to update DEVLINKS= property */
        int devlink_priority;

        char **properties_strv; /* the properties hashmap as a strv */
        uint8_t *properties_nulstr; /* the same as a nulstr */
        size_t properties_nulstr_len;
        bool properties_buf_outdated; /* need to reread hashmap */

        int watch_handle;

        char *syspath;
        const char *devpath;
        const char *sysnum;
        char *sysname;
        bool sysname_set; /* don't reread sysname */

        char *devtype;
        int ifindex;
        char *devname;
        dev_t devnum;

        char *subsystem;
        bool subsystem_set; /* don't reread subsystem */
        char *driver_subsystem; /* only set for the 'drivers' subsystem */
        bool driver_subsystem_set; /* don't reread subsystem */
        char *driver;
        bool driver_set; /* don't reread driver */

        char *id_filename;

        bool is_initialized;
        uint64_t usec_initialized;

        mode_t devmode;
        uid_t devuid;
        gid_t devgid;

        bool uevent_loaded; /* don't reread uevent */
        bool db_loaded; /* don't reread db */

        bool sealed; /* don't read more information from uevent/db */
        bool db_persist; /* don't clean up the db when switching from initrd to real root */
};

typedef enum DeviceAction {
        DEVICE_ACTION_ADD,
        DEVICE_ACTION_REMOVE,
        DEVICE_ACTION_CHANGE,
        DEVICE_ACTION_MOVE,
        DEVICE_ACTION_ONLINE,
        DEVICE_ACTION_OFFLINE,
        DEVICE_ACTION_BIND,
        DEVICE_ACTION_UNBIND,
        _DEVICE_ACTION_MAX,
        _DEVICE_ACTION_INVALID = -1,
} DeviceAction;

int device_new_aux(sd_device **ret);
int device_add_property_aux(sd_device *device, const char *key, const char *value, bool db);
int device_add_property_internal(sd_device *device, const char *key, const char *value);
int device_read_uevent_file(sd_device *device);
int device_read_db_aux(sd_device *device, bool force);

int device_set_syspath(sd_device *device, const char *_syspath, bool verify);
int device_set_ifindex(sd_device *device, const char *ifindex);
int device_set_devmode(sd_device *device, const char *devmode);
int device_set_devname(sd_device *device, const char *_devname);
int device_set_devtype(sd_device *device, const char *_devtype);
int device_set_devnum(sd_device *device, const char *major, const char *minor);
int device_set_subsystem(sd_device *device, const char *_subsystem);
int device_set_driver(sd_device *device, const char *_driver);
int device_set_usec_initialized(sd_device *device, const char *initialized);

DeviceAction device_action_from_string(const char *s) _pure_;
const char *device_action_to_string(DeviceAction a) _const_;
