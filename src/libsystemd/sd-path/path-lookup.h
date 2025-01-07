/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "sd-path.h"

#include "runtime-scope.h"

typedef enum LookupPathsFlags {
        LOOKUP_PATHS_EXCLUDE_GENERATED   = 1 << 0,
        LOOKUP_PATHS_TEMPORARY_GENERATED = 1 << 1,
        LOOKUP_PATHS_SPLIT_USR           = 1 << 2, /* Legacy, use ONLY for image payloads which might be old */
} LookupPathsFlags;

typedef struct LookupPaths {
        /* Where we look for unit files. This includes the individual special paths below, but also any vendor
         * supplied, static unit file paths. */
        char **search_path;

        /* Where we shall create or remove our installation symlinks, aka "configuration", and where the user/admin
         * shall place their own unit files. */
        char *persistent_config;
        char *runtime_config;

        /* Where units from a portable service image shall be placed. */
        char *persistent_attached;
        char *runtime_attached;

        /* Where to place generated unit files (i.e. those a "generator" tool generated). Note the special semantics of
         * this directory: the generators are flushed each time a "systemctl daemon-reload" is issued. The user should
         * not alter these directories directly. */
        char *generator;
        char *generator_early;
        char *generator_late;

        /* Where to place transient unit files (i.e. those created dynamically via the bus API). Note the special
         * semantics of this directory: all units created transiently have their unit files removed as the transient
         * unit is unloaded. The user should not alter this directory directly. */
        char *transient;

        /* Where the snippets created by "systemctl set-property" are placed. Note that for transient units, the
         * snippets are placed in the transient directory though (see above). The user should not alter this directory
         * directly. */
        char *persistent_control;
        char *runtime_control;

        /* The root directory prepended to all items above, or NULL */
        char *root_dir;

        /* A temporary directory when running in test mode, to be nuked */
        char *temporary_dir;
} LookupPaths;

int lookup_paths_init(LookupPaths *lp, RuntimeScope scope, LookupPathsFlags flags, const char *root_dir);
int lookup_paths_init_or_warn(LookupPaths *lp, RuntimeScope scope, LookupPathsFlags flags, const char *root_dir);

void lookup_paths_log(LookupPaths *p);
void lookup_paths_done(LookupPaths *p);

int runtime_directory(RuntimeScope scope, const char *suffix, char **ret);

/* We don't treat /etc/xdg/systemd/ in these functions as the xdg base dir spec suggests because we assume
 * that is a link to /etc/systemd/ anyway. */

int user_search_dirs(const char *suffix, char ***ret_config_dirs, char ***ret_data_dirs);
static inline int xdg_user_runtime_dir(const char *suffix, char **ret) {
        return sd_path_lookup(SD_PATH_USER_RUNTIME, suffix, ret);
}
static inline int xdg_user_config_dir(const char *suffix, char **ret) {
        return sd_path_lookup(SD_PATH_USER_CONFIGURATION, suffix, ret);
}
static inline int xdg_user_data_dir(const char *suffix, char **ret) {
        return sd_path_lookup(SD_PATH_USER_SHARED, suffix, ret);
}

bool path_is_user_data_dir(const char *path);
bool path_is_user_config_dir(const char *path);

char** generator_binary_paths_internal(RuntimeScope scope, bool env_generator);
static inline char** generator_binary_paths(RuntimeScope runtime_scope) {
        return generator_binary_paths_internal(runtime_scope, false);
}
static inline char** env_generator_binary_paths(RuntimeScope runtime_scope) {
        return generator_binary_paths_internal(runtime_scope, true);
}

static inline int credential_store_path(RuntimeScope runtime_scope, char ***ret) {
        return sd_path_lookup_strv(
                        runtime_scope == RUNTIME_SCOPE_SYSTEM ?
                        SD_PATH_SYSTEM_SEARCH_CREDENTIAL_STORE : SD_PATH_USER_SEARCH_CREDENTIAL_STORE,
                        /* suffix= */ NULL,
                        ret);
}

static inline int credential_store_path_encrypted(RuntimeScope runtime_scope, char ***ret) {
        return sd_path_lookup_strv(
                        runtime_scope == RUNTIME_SCOPE_SYSTEM ?
                        SD_PATH_SYSTEM_SEARCH_CREDENTIAL_STORE_ENCRYPTED : SD_PATH_USER_SEARCH_CREDENTIAL_STORE_ENCRYPTED,
                        /* suffix= */ NULL,
                        ret);
}
