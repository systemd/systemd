/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-bus.h"

#include "hashmap.h"
#include "macro.h"
#include "set.h"
#include "string-util.h"

typedef struct PortableMetadata {
        int fd;
        char *source;
        char *image_path;
        char *selinux_label;
        char name[];
} PortableMetadata;

#define PORTABLE_METADATA_IS_OS_RELEASE(m) (streq((m)->name, "/etc/os-release"))
#define PORTABLE_METADATA_IS_EXTENSION_RELEASE(m) (startswith((m)->name, "/usr/lib/extension-release.d/extension-release."))
#define PORTABLE_METADATA_IS_UNIT(m) (!IN_SET((m)->name[0], 0, '/'))

typedef enum PortableFlags {
        PORTABLE_RUNTIME        = 1 << 0, /* Public API via DBUS, do not change */
        PORTABLE_FORCE_ATTACH   = 1 << 1, /* Public API via DBUS, do not change */
        PORTABLE_FORCE_SYSEXT   = 1 << 2, /* Public API via DBUS, do not change */
        PORTABLE_PREFER_COPY    = 1 << 3,
        PORTABLE_PREFER_SYMLINK = 1 << 4,
        PORTABLE_REATTACH       = 1 << 5,
        _PORTABLE_MASK_PUBLIC   = PORTABLE_RUNTIME | PORTABLE_FORCE_ATTACH | PORTABLE_FORCE_SYSEXT,
        _PORTABLE_TYPE_MAX,
        _PORTABLE_TYPE_INVALID  = -EINVAL,
} PortableFlags;

/* This enum is anonymous, since we usually store it in an 'int', as we overload it with negative errno
 * values. */
enum {
        PORTABLE_COPY,
        PORTABLE_SYMLINK,
        PORTABLE_UNLINK,
        PORTABLE_WRITE,
        PORTABLE_MKDIR,
        _PORTABLE_CHANGE_TYPE_MAX,
        _PORTABLE_CHANGE_TYPE_INVALID = -EINVAL,
};

typedef enum PortableState {
        PORTABLE_DETACHED,
        PORTABLE_ATTACHED,
        PORTABLE_ATTACHED_RUNTIME,
        PORTABLE_ENABLED,
        PORTABLE_ENABLED_RUNTIME,
        PORTABLE_RUNNING,
        PORTABLE_RUNNING_RUNTIME,
        _PORTABLE_STATE_MAX,
        _PORTABLE_STATE_INVALID = -EINVAL,
} PortableState;

typedef struct PortableChange {
        int type_or_errno; /* PORTABLE_COPY, PORTABLE_SYMLINK, … if positive, errno if negative */
        char *path;
        char *source;
} PortableChange;

PortableMetadata *portable_metadata_unref(PortableMetadata *i);
DEFINE_TRIVIAL_CLEANUP_FUNC(PortableMetadata*, portable_metadata_unref);

int portable_metadata_hashmap_to_sorted_array(Hashmap *unit_files, PortableMetadata ***ret);

int portable_extract(const char *image, char **matches, char **extension_image_paths, PortableFlags flags, PortableMetadata **ret_os_release, OrderedHashmap **ret_extension_releases, Hashmap **ret_unit_files, char ***ret_valid_prefixes, sd_bus_error *error);

int portable_attach(sd_bus *bus, const char *name_or_path, char **matches, const char *profile, char **extension_images, PortableFlags flags, PortableChange **changes, size_t *n_changes, sd_bus_error *error);
int portable_detach(sd_bus *bus, const char *name_or_path, char **extension_image_paths, PortableFlags flags, PortableChange **changes, size_t *n_changes, sd_bus_error *error);

int portable_get_state(sd_bus *bus, const char *name_or_path, char **extension_image_paths, PortableFlags flags, PortableState *ret, sd_bus_error *error);

int portable_get_profiles(char ***ret);

void portable_changes_free(PortableChange *changes, size_t n_changes);

const char *portable_change_type_to_string(int t) _const_;
int portable_change_type_from_string(const char *t) _pure_;

const char *portable_state_to_string(PortableState t) _const_;
PortableState portable_state_from_string(const char *t) _pure_;
