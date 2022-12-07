/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "macro.h"
#include "unit-def.h"

#define UNIT_NAME_MAX 256

typedef enum UnitNameFlags {
        UNIT_NAME_PLAIN      = 1 << 0, /* Allow foo.service */
        UNIT_NAME_UTEMPLATE  = 1 << 1, /* Allow foo@.service */
        UNIT_NAME_UINSTANCE  = 1 << 2, /* Allow foo@bar.service */
        UNIT_NAME_RTEMPLATE  = 1 << 3, /* Allow foo#.service */
        UNIT_NAME_GENERATION = 1 << 4, /* Allow foo#bar.service */
        UNIT_NAME_TEMPLATE   = UNIT_NAME_UTEMPLATE | UNIT_NAME_RTEMPLATE,
        UNIT_NAME_INSTANCE   = UNIT_NAME_UINSTANCE | UNIT_NAME_GENERATION,
        UNIT_NAME_ANY = UNIT_NAME_PLAIN|UNIT_NAME_TEMPLATE|UNIT_NAME_INSTANCE,
        _UNIT_NAME_INVALID = -EINVAL,
} UnitNameFlags;

typedef struct UnitInstanceArg {
        const char *instance;
        const char *generation;
} UnitInstanceArg;

#define UNIT_ARG_INSTANCE(x)    (UnitInstanceArg) { (x), NULL}
#define UNIT_ARG_GENERATION(x)  (UnitInstanceArg) { NULL, (x)}

static inline void unit_instance_free(UnitInstanceArg i) {
        free((char *)i.instance);
        free((char *)i.generation);
}
static inline void unit_instance_freep(UnitInstanceArg *i) {
        unit_instance_free(*i);
}

bool unit_name_is_valid(const char *n, UnitNameFlags flags) _pure_;
bool unit_prefix_is_valid(const char *p) _pure_;
bool unit_instance_is_null(UnitInstanceArg i) _pure_;
bool unit_instance_is_valid(UnitInstanceArg i) _pure_;
int unit_instance_to_string(UnitInstanceArg i, char **ret);
bool unit_instance_eq(UnitInstanceArg a, UnitInstanceArg b) _pure_;
bool unit_suffix_is_valid(const char *s) _pure_;

int unit_name_to_prefix(const char *n, char **ret);
UnitNameFlags unit_name_to_instance(const char *n, UnitInstanceArg *ret);
static inline UnitNameFlags unit_name_classify(const char *n) {
        return unit_name_to_instance(n, NULL);
}
int unit_name_to_prefix_and_instance(const char *n, char **ret);

UnitType unit_name_to_type(const char *n) _pure_;

int unit_name_change_suffix(const char *n, const char *suffix, char **ret);

int unit_name_build(const char *prefix, UnitInstanceArg instance, const char *suffix, char **ret);
int unit_name_build_from_type(const char *prefix, UnitInstanceArg instance, UnitType, char **ret);

char *unit_name_escape(const char *f);
int unit_name_unescape(const char *f, char **ret);
int unit_name_path_escape(const char *f, char **ret);
int unit_name_path_unescape(const char *f, char **ret);

int unit_name_replace_instance(const char *f, UnitInstanceArg i, char **ret);

int unit_name_template(const char *f, char **ret);
int unit_name_make_rtemplate(const char *f, char **ret);

int unit_name_hash_long(const char *name, char **ret);
bool unit_name_is_hashed(const char *name);

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
