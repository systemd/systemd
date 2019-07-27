/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

typedef enum UnitFilePresetMode UnitFilePresetMode;
typedef enum UnitFileChangeType UnitFileChangeType;
typedef enum UnitFileFlags UnitFileFlags;
typedef enum UnitFileType UnitFileType;
typedef struct UnitFileChange UnitFileChange;
typedef struct UnitFileList UnitFileList;
typedef struct UnitFileInstallInfo UnitFileInstallInfo;

#include <stdbool.h>

#include "hashmap.h"
#include "macro.h"
#include "path-lookup.h"
#include "strv.h"
#include "unit-name.h"

enum UnitFilePresetMode {
        UNIT_FILE_PRESET_FULL,
        UNIT_FILE_PRESET_ENABLE_ONLY,
        UNIT_FILE_PRESET_DISABLE_ONLY,
        _UNIT_FILE_PRESET_MAX,
        _UNIT_FILE_PRESET_INVALID = -1
};

enum UnitFileChangeType {
        UNIT_FILE_SYMLINK,
        UNIT_FILE_UNLINK,
        UNIT_FILE_IS_MASKED,
        UNIT_FILE_IS_DANGLING,
        _UNIT_FILE_CHANGE_TYPE_MAX,
        _UNIT_FILE_CHANGE_TYPE_INVALID = INT_MIN
};

enum UnitFileFlags {
        UNIT_FILE_RUNTIME = 1 << 0,
        UNIT_FILE_FORCE   = 1 << 1,
        UNIT_FILE_DRY_RUN = 1 << 2,
};

/* type can either one of the UnitFileChangeTypes listed above, or a negative error.
 * If source is specified, it should be the contents of the path symlink.
 * In case of an error, source should be the existing symlink contents or NULL
 */
struct UnitFileChange {
        int type; /* UnitFileChangeType or bust */
        char *path;
        char *source;
};

static inline bool unit_file_changes_have_modification(const UnitFileChange* changes, size_t n_changes) {
        size_t i;
        for (i = 0; i < n_changes; i++)
                if (IN_SET(changes[i].type, UNIT_FILE_SYMLINK, UNIT_FILE_UNLINK))
                        return true;
        return false;
}

struct UnitFileList {
        char *path;
        UnitFileState state;
};

enum UnitFileType {
        UNIT_FILE_TYPE_REGULAR,
        UNIT_FILE_TYPE_SYMLINK,
        UNIT_FILE_TYPE_MASKED,
        _UNIT_FILE_TYPE_MAX,
        _UNIT_FILE_TYPE_INVALID = -1,
};

struct UnitFileInstallInfo {
        char *name;
        char *path;

        char **aliases;
        char **wanted_by;
        char **required_by;
        char **also;

        char *default_instance;
        char *symlink_target;

        UnitFileType type;
        bool auxiliary;
};

int unit_file_enable(
                UnitFileScope scope,
                UnitFileFlags flags,
                const char *root_dir,
                char **files,
                UnitFileChange **changes,
                size_t *n_changes);
int unit_file_disable(
                UnitFileScope scope,
                UnitFileFlags flags,
                const char *root_dir,
                char **files,
                UnitFileChange **changes,
                size_t *n_changes);
int unit_file_reenable(
                UnitFileScope scope,
                UnitFileFlags flags,
                const char *root_dir,
                char **files,
                UnitFileChange **changes,
                size_t *n_changes);
int unit_file_preset(
                UnitFileScope scope,
                UnitFileFlags flags,
                const char *root_dir,
                char **files,
                UnitFilePresetMode mode,
                UnitFileChange **changes,
                size_t *n_changes);
int unit_file_preset_all(
                UnitFileScope scope,
                UnitFileFlags flags,
                const char *root_dir,
                UnitFilePresetMode mode,
                UnitFileChange **changes,
                size_t *n_changes);
int unit_file_mask(
                UnitFileScope scope,
                UnitFileFlags flags,
                const char *root_dir,
                char **files,
                UnitFileChange **changes,
                size_t *n_changes);
int unit_file_unmask(
                UnitFileScope scope,
                UnitFileFlags flags,
                const char *root_dir,
                char **files,
                UnitFileChange **changes,
                size_t *n_changes);
int unit_file_link(
                UnitFileScope scope,
                UnitFileFlags flags,
                const char *root_dir,
                char **files,
                UnitFileChange **changes,
                size_t *n_changes);
int unit_file_revert(
                UnitFileScope scope,
                const char *root_dir,
                char **files,
                UnitFileChange **changes,
                size_t *n_changes);
int unit_file_set_default(
                UnitFileScope scope,
                UnitFileFlags flags,
                const char *root_dir,
                const char *file,
                UnitFileChange **changes,
                size_t *n_changes);
int unit_file_get_default(
                UnitFileScope scope,
                const char *root_dir,
                char **name);
int unit_file_add_dependency(
                UnitFileScope scope,
                UnitFileFlags flags,
                const char *root_dir,
                char **files,
                const char *target,
                UnitDependency dep,
                UnitFileChange **changes,
                size_t *n_changes);

int unit_file_lookup_state(
                UnitFileScope scope,
                const LookupPaths *paths,
                const char *name,
                UnitFileState *ret);

int unit_file_get_state(UnitFileScope scope, const char *root_dir, const char *filename, UnitFileState *ret);
int unit_file_exists(UnitFileScope scope, const LookupPaths *paths, const char *name);

int unit_file_get_list(UnitFileScope scope, const char *root_dir, Hashmap *h, char **states, char **patterns);
Hashmap* unit_file_list_free(Hashmap *h);

int unit_file_changes_add(UnitFileChange **changes, size_t *n_changes, UnitFileChangeType type, const char *path, const char *source);
void unit_file_changes_free(UnitFileChange *changes, size_t n_changes);
void unit_file_dump_changes(int r, const char *verb, const UnitFileChange *changes, size_t n_changes, bool quiet);

int unit_file_query_preset(UnitFileScope scope, const char *root_dir, const char *name);

const char *unit_file_state_to_string(UnitFileState s) _const_;
UnitFileState unit_file_state_from_string(const char *s) _pure_;
/* from_string conversion is unreliable because of the overlap between -EPERM and -1 for error. */

const char *unit_file_change_type_to_string(UnitFileChangeType s) _const_;
UnitFileChangeType unit_file_change_type_from_string(const char *s) _pure_;

const char *unit_file_preset_mode_to_string(UnitFilePresetMode m) _const_;
UnitFilePresetMode unit_file_preset_mode_from_string(const char *s) _pure_;
