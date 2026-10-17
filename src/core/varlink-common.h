/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "core-forward.h"

int rlimit_build_json(sd_json_variant **ret, const char *name, void *userdata);
int rlimit_table_build_json(sd_json_variant **ret, const char *name, void *userdata);
int cpuset_build_json(sd_json_variant **ret, const char *name, void *userdata);
const char* varlink_error_id_from_bus_error(const sd_bus_error *e);
int exec_command_build_json(sd_json_variant **ret, const char *name, void *userdata);
int exec_command_list_build_json(sd_json_variant **ret, const char *name, void *userdata);
int exec_command_status_build_json(sd_json_variant **ret, const char *name, void *userdata);
int exec_command_status_list_build_json(sd_json_variant **ret, const char *name, void *userdata);
int varlink_reply_bus_error(sd_varlink *link, int r, const sd_bus_error *e);

/* Apply helpers return 0 for absent fields, 1 for applied settings (even if unchanged), or a negative error.
 * Negative tristates/enums and NULL strings represent absent fields. */
int varlink_apply_tristate_bool(Unit *u, const char *name, bool *p, int value, UnitWriteFlags flags);
int varlink_apply_string(Unit *u, const char *name, char **p, const char *value, UnitWriteFlags flags);
int varlink_apply_string_escaped(Unit *u, const char *name, char **p, const char *value, UnitWriteFlags flags);
int varlink_apply_absolute_path(Unit *u, const char *name, char **p, const char *value, UnitWriteFlags flags);

/* NULL means absent; a non-NULL empty list clears. Otherwise appends with deduplication and serializes
 * space-separated entries without quoting. Callers validate entries. */
int varlink_apply_strv(Unit *u, const char *name, char ***p, char **value, UnitWriteFlags flags);
int varlink_apply_strv_escaped(Unit *u, const char *name, char ***p, char **value, UnitWriteFlags flags);

int varlink_apply_uint64_limit(Unit *u, const char *name, uint64_t *p, uint64_t value, uint64_t minimum, UnitWriteFlags flags);

/* Takes a unit-file directive name; callers check field presence. Uses microsecond accuracy
 * and serializes infinity as an empty assignment, matching the corresponding D-Bus setters. */
int varlink_apply_usec_empty_on_infinity(Unit *u, const char *name, usec_t *p, usec_t value, UnitWriteFlags flags);

/* Nonnegative enum values must have a string representation, as guaranteed by their dispatchers. */
#define DEFINE_VARLINK_APPLY_ENUM(prefix, type, to_string)                                     \
        int varlink_apply_enum_##prefix(                                                       \
                        Unit *u,                                                               \
                        const char *name,                                                      \
                        type *p,                                                               \
                        type value,                                                            \
                        bool (*refuse)(type),                                                  \
                        UnitWriteFlags flags) {                                                \
                assert(name);                                                                  \
                assert(p);                                                                     \
                                                                                               \
                if (value < 0)                                                                 \
                        return 0;                                                              \
                if (refuse && refuse(value))                                                   \
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),                        \
                                               "%s=%s is not supported via Varlink.",          \
                                               name, ASSERT_PTR((to_string)(value)));          \
                                                                                               \
                *p = value;                                                                    \
                const char *s = ASSERT_PTR((to_string)(value));                                \
                unit_write_settingf(u, flags, name, "%s=%s", name, s);                         \
                return 1;                                                                      \
        }
