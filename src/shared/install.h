/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "runtime-scope.h"
#include "unit-file.h"

typedef enum UnitFilePresetMode {
        UNIT_FILE_PRESET_FULL,
        UNIT_FILE_PRESET_ENABLE_ONLY,
        UNIT_FILE_PRESET_DISABLE_ONLY,
        _UNIT_FILE_PRESET_MODE_MAX,
        _UNIT_FILE_PRESET_MODE_INVALID = -EINVAL,
} UnitFilePresetMode;

typedef enum InstallChangeType {
        INSTALL_CHANGE_SYMLINK,
        INSTALL_CHANGE_UNLINK,
        INSTALL_CHANGE_IS_MASKED,
        INSTALL_CHANGE_IS_MASKED_GENERATOR,
        INSTALL_CHANGE_IS_DANGLING,
        INSTALL_CHANGE_DESTINATION_NOT_PRESENT,
        INSTALL_CHANGE_AUXILIARY_FAILED,
        _INSTALL_CHANGE_TYPE_MAX,
        _INSTALL_CHANGE_INVALID = -EINVAL,
        _INSTALL_CHANGE_ERRNO_MAX = -ERRNO_MAX, /* Ensure this type covers the whole negative errno range */
} InstallChangeType;

static inline bool INSTALL_CHANGE_TYPE_VALID(InstallChangeType t) {
        return t >= _INSTALL_CHANGE_ERRNO_MAX && t < _INSTALL_CHANGE_TYPE_MAX;
}

typedef enum UnitFileFlags {
        UNIT_FILE_RUNTIME                  = 1 << 0, /* Public API via DBUS, do not change */
        UNIT_FILE_FORCE                    = 1 << 1, /* Public API via DBUS, do not change */
        UNIT_FILE_PORTABLE                 = 1 << 2, /* Public API via DBUS, do not change */
        UNIT_FILE_DRY_RUN                  = 1 << 3,
        UNIT_FILE_IGNORE_AUXILIARY_FAILURE = 1 << 4,
        _UNIT_FILE_FLAGS_MASK_PUBLIC = UNIT_FILE_RUNTIME|UNIT_FILE_PORTABLE|UNIT_FILE_FORCE,
} UnitFileFlags;

/* type can be either one of the INSTALL_CHANGE_SYMLINK, INSTALL_CHANGE_UNLINK, … listed above, or a negative
 * errno value.
 *
 * If source is specified, it should be the contents of the path symlink. In case of an error, source should
 * be the existing symlink contents or NULL. */
typedef struct InstallChange {
        int type; /* INSTALL_CHANGE_SYMLINK, … if positive, errno if negative */
        char *path;
        char *source;
} InstallChange;

static inline bool install_changes_have_modification(const InstallChange *changes, size_t n_changes) {
        FOREACH_ARRAY(i, changes, n_changes)
                if (IN_SET(i->type, INSTALL_CHANGE_SYMLINK, INSTALL_CHANGE_UNLINK))
                        return true;
        return false;
}

typedef struct UnitFileList {
        char *path;
        UnitFileState state;
} UnitFileList;

typedef enum InstallMode {
        INSTALL_MODE_REGULAR,
        INSTALL_MODE_LINKED,
        INSTALL_MODE_ALIAS,
        INSTALL_MODE_MASKED,
        _INSTALL_MODE_MAX,
        _INSTALL_MODE_INVALID = -EINVAL,
} InstallMode;

typedef struct InstallInfo {
        char *name;
        char *path;
        char *root;

        char **aliases;
        char **wanted_by;
        char **required_by;
        char **upheld_by;
        char **also;

        char *default_instance;
        char *symlink_target;

        InstallMode install_mode;
        bool auxiliary;
} InstallInfo;

int unit_file_enable(
                RuntimeScope scope,
                UnitFileFlags flags,
                const char *root_dir,
                char * const *names_or_paths,
                InstallChange **changes,
                size_t *n_changes);
int unit_file_disable(
                RuntimeScope scope,
                UnitFileFlags flags,
                const char *root_dir,
                char * const *names,
                InstallChange **changes,
                size_t *n_changes);
int unit_file_reenable(
                RuntimeScope scope,
                UnitFileFlags flags,
                const char *root_dir,
                char * const *names_or_paths,
                InstallChange **changes,
                size_t *n_changes);
int unit_file_preset(
                RuntimeScope scope,
                UnitFileFlags file_flags,
                const char *root_dir,
                char * const *names,
                UnitFilePresetMode mode,
                InstallChange **changes,
                size_t *n_changes);
int unit_file_preset_all(
                RuntimeScope scope,
                UnitFileFlags file_flags,
                const char *root_dir,
                UnitFilePresetMode mode,
                InstallChange **changes,
                size_t *n_changes);
int unit_file_mask(
                RuntimeScope scope,
                UnitFileFlags flags,
                const char *root_dir,
                char * const *names,
                InstallChange **changes,
                size_t *n_changes);
int unit_file_unmask(
                RuntimeScope scope,
                UnitFileFlags flags,
                const char *root_dir,
                char * const *names,
                InstallChange **changes,
                size_t *n_changes);
int unit_file_link(
                RuntimeScope scope,
                UnitFileFlags flags,
                const char *root_dir,
                char * const *files,
                InstallChange **changes,
                size_t *n_changes);
int unit_file_revert(
                RuntimeScope scope,
                const char *root_dir,
                char * const *names,
                InstallChange **changes,
                size_t *n_changes);
int unit_file_set_default(
                RuntimeScope scope,
                UnitFileFlags flags,
                const char *root_dir,
                const char *name,
                InstallChange **changes,
                size_t *n_changes);
int unit_file_get_default(
                RuntimeScope scope,
                const char *root_dir,
                char **ret);
int unit_file_add_dependency(
                RuntimeScope scope,
                UnitFileFlags flags,
                const char *root_dir,
                char * const *names,
                const char *target,
                UnitDependency dep,
                InstallChange **changes,
                size_t *n_changes);

int unit_file_lookup_state(
                RuntimeScope scope,
                const LookupPaths *paths,
                const char *name,
                UnitFileState *ret);

int unit_file_get_state(RuntimeScope scope, const char *root_dir, const char *filename, UnitFileState *ret);

int unit_file_exists_full(RuntimeScope scope, const LookupPaths *paths, const char *name, char **ret_path);
static inline int unit_file_exists(RuntimeScope scope, const LookupPaths *paths, const char *name) {
        return unit_file_exists_full(scope, paths, name, NULL);
}

int unit_file_get_list(RuntimeScope scope, const char *root_dir, char * const *states, char * const *patterns, Hashmap **ret);

InstallChangeType install_changes_add(InstallChange **changes, size_t *n_changes, InstallChangeType type, const char *path, const char *source);
void install_changes_free(InstallChange *changes, size_t n_changes);

int install_change_dump_error(const InstallChange *change, char **ret_errmsg, const char **ret_bus_error);
void install_changes_dump(
                int error,
                const char *verb,
                const InstallChange *changes,
                size_t n_changes,
                bool quiet);

int unit_file_verify_alias(
                const InstallInfo *info,
                const char *dst,
                char **ret_dst,
                InstallChange **changes,
                size_t *n_changes);

typedef struct UnitFilePresetRule UnitFilePresetRule;

typedef struct {
        UnitFilePresetRule *rules;
        size_t n_rules;
        bool initialized;
} UnitFilePresets;

typedef enum PresetAction {
        PRESET_UNKNOWN,
        PRESET_ENABLE,
        PRESET_DISABLE,
        PRESET_IGNORE,
        _PRESET_ACTION_MAX,
        _PRESET_ACTION_INVALID = -EINVAL,
        _PRESET_ACTION_ERRNO_MAX = -ERRNO_MAX, /* Ensure this type covers the whole negative errno range */
} PresetAction;

const char* preset_action_past_tense_to_string(PresetAction action);

void unit_file_presets_done(UnitFilePresets *p);
PresetAction unit_file_query_preset(RuntimeScope scope, const char *root_dir, const char *name, UnitFilePresets *cached);

const char* unit_file_state_to_string(UnitFileState s) _const_;
UnitFileState unit_file_state_from_string(const char *s) _pure_;
/* from_string conversion is unreliable because of the overlap between -EPERM and -1 for error. */

const char* install_change_type_to_string(InstallChangeType t) _const_;
InstallChangeType install_change_type_from_string(const char *s) _pure_;

const char* unit_file_preset_mode_to_string(UnitFilePresetMode m) _const_;
UnitFilePresetMode unit_file_preset_mode_from_string(const char *s) _pure_;
