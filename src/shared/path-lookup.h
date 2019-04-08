/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>

typedef struct LookupPaths LookupPaths;

#include "install.h"
#include "macro.h"

typedef enum LookupPathsFlags {
        LOOKUP_PATHS_EXCLUDE_GENERATED   = 1 << 0,
        LOOKUP_PATHS_TEMPORARY_GENERATED = 1 << 1,
        LOOKUP_PATHS_SPLIT_USR           = 1 << 2,
} LookupPathsFlags;

struct LookupPaths {
        /* Where we look for unit files. This includes the individual special paths below, but also any vendor
         * supplied, static unit file paths. */
        char **search_path;

        /* Where we shall create or remove our installation symlinks, aka "configuration", and where the user/admin
         * shall place his own unit files. */
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
};

int lookup_paths_init(LookupPaths *p, UnitFileScope scope, LookupPathsFlags flags, const char *root_dir);

int xdg_user_dirs(char ***ret_config_dirs, char ***ret_data_dirs);
int xdg_user_runtime_dir(char **ret, const char *suffix);
int xdg_user_config_dir(char **ret, const char *suffix);
int xdg_user_data_dir(char **ret, const char *suffix);

bool path_is_user_data_dir(const char *path);
bool path_is_user_config_dir(const char *path);

int lookup_paths_reduce(LookupPaths *p);

int lookup_paths_mkdir_generator(LookupPaths *p);
void lookup_paths_trim_generator(LookupPaths *p);
void lookup_paths_flush_generator(LookupPaths *p);

void lookup_paths_free(LookupPaths *p);

char **generator_binary_paths(UnitFileScope scope);
