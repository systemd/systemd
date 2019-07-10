/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>

#include "hashmap.h"
#include "time-util.h"
#include "unit-name.h"

typedef enum UnitFileState UnitFileState;
typedef enum UnitFileScope UnitFileScope;
typedef struct LookupPaths LookupPaths;

enum UnitFileState {
        UNIT_FILE_ENABLED,
        UNIT_FILE_ENABLED_RUNTIME,
        UNIT_FILE_LINKED,
        UNIT_FILE_LINKED_RUNTIME,
        UNIT_FILE_MASKED,
        UNIT_FILE_MASKED_RUNTIME,
        UNIT_FILE_STATIC,
        UNIT_FILE_DISABLED,
        UNIT_FILE_INDIRECT,
        UNIT_FILE_GENERATED,
        UNIT_FILE_TRANSIENT,
        UNIT_FILE_BAD,
        _UNIT_FILE_STATE_MAX,
        _UNIT_FILE_STATE_INVALID = -1
};

enum UnitFileScope {
        UNIT_FILE_SYSTEM,
        UNIT_FILE_GLOBAL,
        UNIT_FILE_USER,
        _UNIT_FILE_SCOPE_MAX,
        _UNIT_FILE_SCOPE_INVALID = -1
};

bool unit_type_may_alias(UnitType type) _const_;
bool unit_type_may_template(UnitType type) _const_;

int unit_validate_alias_symlink_and_warn(const char *filename, const char *target);

int unit_file_build_name_map(
                const LookupPaths *lp,
                usec_t *ret_time,
                Hashmap **ret_unit_ids_map,
                Hashmap **ret_unit_names_map,
                Set **ret_path_cache);

int unit_file_find_fragment(
                Hashmap *unit_ids_map,
                Hashmap *unit_name_map,
                const char *unit_name,
                const char **ret_fragment_path,
                Set **names);
