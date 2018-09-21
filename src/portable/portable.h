/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "sd-bus.h"

#include "hashmap.h"
#include "macro.h"
#include "set.h"
#include "string-util.h"

typedef struct PortableMetadata {
        int fd;
        char *source;
        char name[];
} PortableMetadata;

#define PORTABLE_METADATA_IS_OS_RELEASE(m) (streq((m)->name, "/etc/os-release"))
#define PORTABLE_METADATA_IS_UNIT(m) (!IN_SET((m)->name[0], 0, '/'))

typedef enum PortableFlags {
        PORTABLE_PREFER_COPY    = 1 << 0,
        PORTABLE_PREFER_SYMLINK = 1 << 1,
        PORTABLE_RUNTIME        = 1 << 2,
} PortableFlags;

typedef enum PortableChangeType {
        PORTABLE_COPY,
        PORTABLE_SYMLINK,
        PORTABLE_UNLINK,
        PORTABLE_WRITE,
        PORTABLE_MKDIR,
        _PORTABLE_CHANGE_TYPE_MAX,
        _PORTABLE_CHANGE_TYPE_INVALID = INT_MIN,
} PortableChangeType;

typedef enum PortableState {
        PORTABLE_DETACHED,
        PORTABLE_ATTACHED,
        PORTABLE_ATTACHED_RUNTIME,
        PORTABLE_ENABLED,
        PORTABLE_ENABLED_RUNTIME,
        PORTABLE_RUNNING,
        PORTABLE_RUNNING_RUNTIME,
        _PORTABLE_STATE_MAX,
        _PORTABLE_STATE_INVALID = -1
} PortableState;

typedef struct PortableChange {
        int type; /* PortableFileChangeType or negative error number */
        char *path;
        char *source;
} PortableChange;

PortableMetadata *portable_metadata_unref(PortableMetadata *i);
DEFINE_TRIVIAL_CLEANUP_FUNC(PortableMetadata*, portable_metadata_unref);

Hashmap *portable_metadata_hashmap_unref(Hashmap *h);
DEFINE_TRIVIAL_CLEANUP_FUNC(Hashmap*, portable_metadata_hashmap_unref);

int portable_metadata_hashmap_to_sorted_array(Hashmap *unit_files, PortableMetadata ***ret);

int portable_extract(const char *image, char **matches, PortableMetadata **ret_os_release, Hashmap **ret_unit_files, sd_bus_error *error);

int portable_attach(sd_bus *bus, const char *name_or_path, char **matches, const char *profile, PortableFlags flags, PortableChange **changes, size_t *n_changes, sd_bus_error *error);
int portable_detach(sd_bus *bus, const char *name_or_path, PortableFlags flags, PortableChange **changes, size_t *n_changes, sd_bus_error *error);

int portable_get_state(sd_bus *bus, const char *name_or_path, PortableFlags flags, PortableState *ret, sd_bus_error *error);

int portable_get_profiles(char ***ret);

void portable_changes_free(PortableChange *changes, size_t n_changes);

const char *portable_change_type_to_string(PortableChangeType t) _const_;
PortableChangeType portable_change_type_from_string(const char *t) _pure_;

const char *portable_state_to_string(PortableState t) _const_;
PortableState portable_state_from_string(const char *t) _pure_;
