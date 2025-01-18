/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-device.h"

#include "device-private.h"
#include "hashmap.h"
#include "set.h"
#include "time-util.h"

#define LATEST_UDEV_DATABASE_VERSION 1

struct sd_device {
        unsigned n_ref;

        /* The database version indicates the supported features by the udev database.
         * This is saved and parsed in V field.
         *
         * 0: None of the following features are supported (systemd version <= 246).
         * 1: The current tags (Q) and the database version (V) features are implemented (>= 247).
         */
        unsigned database_version;

        sd_device *parent;

        OrderedHashmap *properties;
        Iterator properties_iterator;
        uint64_t properties_generation; /* changes whenever the properties are changed */
        uint64_t properties_iterator_generation; /* generation when iteration was started */

        /* the subset of the properties that should be written to the db */
        OrderedHashmap *properties_db;

        Hashmap *sysattr_values; /* cached sysattr values */

        Set *sysattrs; /* names of sysattrs */
        Iterator sysattrs_iterator;

        Set *all_tags, *current_tags;
        Iterator all_tags_iterator, current_tags_iterator;
        uint64_t all_tags_iterator_generation, current_tags_iterator_generation; /* generation when iteration was started */
        uint64_t tags_generation; /* changes whenever the tags are changed */

        Set *devlinks;
        Iterator devlinks_iterator;
        uint64_t devlinks_generation; /* changes whenever the devlinks are changed */
        uint64_t devlinks_iterator_generation; /* generation when iteration was started */
        int devlink_priority;

        Hashmap *children;
        Iterator children_iterator;
        bool children_enumerated;

        int ifindex;
        char *devtype;
        char *devname;
        dev_t devnum;

        char **properties_strv; /* the properties hashmap as a strv */
        char *properties_nulstr; /* the same as a nulstr */
        size_t properties_nulstr_len;

        char *syspath;
        const char *devpath;
        const char *sysnum;
        char *sysname;

        char *subsystem;
        char *driver_subsystem; /* only set for the 'drivers' subsystem */
        char *driver;

        char *device_id;

        usec_t usec_initialized;

        mode_t devmode;
        uid_t devuid;
        gid_t devgid;

        uint64_t diskseq; /* Block device sequence number, monothonically incremented by the kernel on create/attach */

        /* only set when device is passed through netlink */
        sd_device_action_t action;
        uint64_t seqnum;

        bool parent_set:1; /* no need to try to reload parent */
        bool sysattrs_read:1; /* don't try to re-read sysattrs once read */
        bool property_tags_outdated:1; /* need to update TAGS= or CURRENT_TAGS= property */
        bool property_devlinks_outdated:1; /* need to update DEVLINKS= property */
        bool properties_buf_outdated:1; /* need to reread hashmap */
        bool subsystem_set:1; /* don't reread subsystem */
        bool driver_set:1; /* don't reread driver */
        bool uevent_loaded:1; /* don't reread uevent */
        bool db_loaded; /* don't reread db */

        bool is_initialized:1;
        bool sealed:1; /* don't read more information from uevent/db */
        bool db_persist:1; /* don't clean up the db when switching from initrd to real root */
};

int device_new_aux(sd_device **ret);
int device_add_property_aux(sd_device *device, const char *key, const char *value, bool db);
static inline int device_add_property_internal(sd_device *device, const char *key, const char *value) {
        return device_add_property_aux(device, key, value, false);
}

int device_set_syspath(sd_device *device, const char *_syspath, bool verify);
int device_set_ifindex(sd_device *device, const char *ifindex);
int device_set_devuid(sd_device *device, const char *uid);
int device_set_devgid(sd_device *device, const char *gid);
int device_set_devmode(sd_device *device, const char *devmode);
int device_set_devname(sd_device *device, const char *devname);
int device_set_devtype(sd_device *device, const char *devtype);
int device_set_devnum(sd_device *device, const char *major, const char *minor);
int device_set_subsystem(sd_device *device, const char *subsystem);
int device_set_diskseq(sd_device *device, const char *str);
int device_set_drivers_subsystem(sd_device *device);
int device_set_driver(sd_device *device, const char *driver);
int device_set_usec_initialized(sd_device *device, usec_t when);
