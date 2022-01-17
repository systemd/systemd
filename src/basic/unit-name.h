/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <linux/limits.h>

#include "macro.h"
#include "unit-def.h"

#define UNIT_NAME_MAX 256

typedef enum UnitNameFlags {
        UNIT_NAME_PLAIN    = 1 << 0, /* Allow foo.service */
        UNIT_NAME_TEMPLATE = 1 << 1, /* Allow foo@.service */
        UNIT_NAME_INSTANCE = 1 << 2, /* Allow foo@bar.service */
        UNIT_NAME_ANY = UNIT_NAME_PLAIN|UNIT_NAME_TEMPLATE|UNIT_NAME_INSTANCE,
        _UNIT_NAME_INVALID = -EINVAL,
} UnitNameFlags;

#define UNIT_NAME_MAX_LONG    PATH_MAX-1
#define UNIT_NAME_MAX_DEFAULT 256

static inline size_t unit_name_max_length(UnitType type) {
    assert(type != _UNIT_TYPE_INVALID && type < _UNIT_TYPE_MAX);
    if (IN_SET(type, UNIT_DEVICE, UNIT_MOUNT, UNIT_SWAP))
            /* We allow longer unit names for types where unit can get created because of external event
             * outside of our control (e.g. device is connected or admin mounts a filesystem by hand). */
            return UNIT_NAME_MAX_LONG;
    return UNIT_NAME_MAX_DEFAULT;
}

bool unit_name_is_valid(const char *n, UnitNameFlags flags) _pure_;
bool unit_prefix_is_valid(const char *p) _pure_;
bool unit_instance_is_valid(const char *i) _pure_;
bool unit_suffix_is_valid(const char *s) _pure_;

int unit_name_to_prefix(const char *n, char **ret);
UnitNameFlags unit_name_to_instance(const char *n, char **ret);
static inline UnitNameFlags unit_name_classify(const char *n) {
        return unit_name_to_instance(n, NULL);
}
int unit_name_to_prefix_and_instance(const char *n, char **ret);

UnitType unit_name_to_type(const char *n) _pure_;

int unit_name_change_suffix(const char *n, const char *suffix, char **ret);

int unit_name_build(const char *prefix, const char *instance, const char *suffix, char **ret);
int unit_name_build_from_type(const char *prefix, const char *instance, UnitType, char **ret);

char *unit_name_escape(const char *f);
int unit_name_unescape(const char *f, char **ret);
int unit_name_path_escape(const char *f, char **ret);
int unit_name_path_unescape(const char *f, char **ret);

int unit_name_replace_instance(const char *f, const char *i, char **ret);

int unit_name_template(const char *f, char **ret);

int unit_name_from_path(const char *path, const char *suffix, char **ret);
int unit_name_from_path_instance(const char *prefix, const char *path, const char *suffix, char **ret);
int unit_name_to_path(const char *name, char **ret);

typedef enum UnitNameMangle {
        UNIT_NAME_MANGLE_GLOB = 1 << 0,
        UNIT_NAME_MANGLE_WARN = 1 << 1,
} UnitNameMangle;

int unit_name_mangle_with_suffix(const char *name, const char *operation, UnitNameMangle flags, const char *suffix, char **ret);

static inline int unit_name_mangle(const char *name, UnitNameMangle flags, char **ret) {
        return unit_name_mangle_with_suffix(name, NULL, flags, ".service", ret);
}

int slice_build_parent_slice(const char *slice, char **ret);
int slice_build_subslice(const char *slice, const char *name, char **subslice);
bool slice_name_is_valid(const char *name);

bool unit_name_prefix_equal(const char *a, const char *b);
