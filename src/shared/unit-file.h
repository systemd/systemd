/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "unit-def.h"

typedef enum UnitFileState {
        UNIT_FILE_ENABLED,
        UNIT_FILE_ENABLED_RUNTIME,
        UNIT_FILE_LINKED,
        UNIT_FILE_LINKED_RUNTIME,
        UNIT_FILE_ALIAS,
        UNIT_FILE_MASKED,
        UNIT_FILE_MASKED_RUNTIME,
        UNIT_FILE_STATIC,
        UNIT_FILE_DISABLED,
        UNIT_FILE_INDIRECT,
        UNIT_FILE_GENERATED,
        UNIT_FILE_TRANSIENT,
        UNIT_FILE_BAD,
        _UNIT_FILE_STATE_MAX,
        _UNIT_FILE_STATE_INVALID = -EINVAL,
} UnitFileState;

static inline bool unit_type_may_alias(UnitType type) {
        return IN_SET(type,
                      UNIT_SERVICE,
                      UNIT_SOCKET,
                      UNIT_TARGET,
                      UNIT_DEVICE,
                      UNIT_TIMER,
                      UNIT_PATH);
}

static inline bool unit_type_may_template(UnitType type) {
        return IN_SET(type,
                      UNIT_SERVICE,
                      UNIT_SOCKET,
                      UNIT_TARGET,
                      UNIT_TIMER,
                      UNIT_PATH);
}

int unit_symlink_name_compatible(const char *symlink, const char *target, bool instance_propagation);
int unit_validate_alias_symlink_or_warn(int log_level, const char *filename, const char *target);

bool lookup_paths_timestamp_hash_same(const LookupPaths *lp, uint64_t timestamp_hash, uint64_t *ret_new);

int unit_file_resolve_symlink(
                const char *root_dir,
                char **search_path,
                const char *dir,
                int dirfd,
                const char *filename,
                bool resolve_destination_target,
                char **ret_destination);

int unit_file_build_name_map(
                const LookupPaths *lp,
                uint64_t *cache_timestamp_hash,
                Hashmap **unit_ids_map,
                Hashmap **unit_names_map,
                Set **path_cache);

int unit_file_remove_from_name_map(
                const LookupPaths *lp,
                uint64_t *cache_timestamp_hash,
                Hashmap **unit_ids_map,
                Hashmap **unit_names_map,
                Set **path_cache,
                const char *path);

int unit_file_find_fragment(
                Hashmap *unit_ids_map,
                Hashmap *unit_name_map,
                const char *unit_name,
                const char **ret_fragment_path,
                Set **ret_names);

const char* runlevel_to_target(const char *rl);
