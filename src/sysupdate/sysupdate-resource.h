/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <stdbool.h>
#include <sys/types.h>

#include "sd-id128.h"

#include "hashmap.h"
#include "macro.h"

/* Forward declare this type so that the headers below can use it */
typedef struct Resource Resource;

#include "sysupdate-instance.h"

typedef enum ResourceType {
        RESOURCE_URL_FILE,
        RESOURCE_URL_TAR,
        RESOURCE_TAR,
        RESOURCE_PARTITION,
        RESOURCE_REGULAR_FILE,
        RESOURCE_DIRECTORY,
        RESOURCE_SUBVOLUME,
        _RESOURCE_TYPE_MAX,
        _RESOURCE_TYPE_INVALID = -EINVAL,
} ResourceType;

static inline bool RESOURCE_IS_SOURCE(ResourceType t) {
        return IN_SET(t,
                      RESOURCE_URL_FILE,
                      RESOURCE_URL_TAR,
                      RESOURCE_TAR,
                      RESOURCE_REGULAR_FILE,
                      RESOURCE_DIRECTORY,
                      RESOURCE_SUBVOLUME);
}

static inline bool RESOURCE_IS_TARGET(ResourceType t) {
        return IN_SET(t,
                      RESOURCE_PARTITION,
                      RESOURCE_REGULAR_FILE,
                      RESOURCE_DIRECTORY,
                      RESOURCE_SUBVOLUME);
}

/* Returns true for all resources that deal with file system objects, i.e. where we operate on top of the
 * file system layer, instead of below. */
static inline bool RESOURCE_IS_FILESYSTEM(ResourceType t) {
        return IN_SET(t,
                      RESOURCE_TAR,
                      RESOURCE_REGULAR_FILE,
                      RESOURCE_DIRECTORY,
                      RESOURCE_SUBVOLUME);
}

static inline bool RESOURCE_IS_TAR(ResourceType t) {
        return IN_SET(t,
                      RESOURCE_TAR,
                      RESOURCE_URL_TAR);
}

static inline bool RESOURCE_IS_URL(ResourceType t) {
        return IN_SET(t,
                      RESOURCE_URL_TAR,
                      RESOURCE_URL_FILE);
}

struct Resource {
        ResourceType type;

        /* Where to look for instances, and what to match precisely */
        char *path;
        bool path_auto; /* automatically find root path (only available if target resource, not source resource) */
        char **patterns;
        sd_id128_t partition_type;
        bool partition_type_set;

        /* All instances of this resource we found */
        Instance **instances;
        size_t n_instances;

        /* If this is a partition resource (RESOURCE_PARTITION), then how many partition slots are currently unassigned, that we can use */
        size_t n_empty;
};

void resource_destroy(Resource *rr);

int resource_load_instances(Resource *rr, bool verify, Hashmap **web_cache);

Instance* resource_find_instance(Resource *rr, const char *version);

int resource_resolve_path(Resource *rr, const char *root, const char *node);

ResourceType resource_type_from_string(const char *s) _pure_;
const char *resource_type_to_string(ResourceType t) _const_;
