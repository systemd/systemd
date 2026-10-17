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

/* Negative tristates/enums and NULL strings represent absent fields.
 * The tristate boolean helper always returns 0 for compatibility with property apply callbacks. */
int varlink_apply_tristate_bool(Unit *u, const char *name, bool *p, int value, UnitWriteFlags flags);
int varlink_apply_string(Unit *u, const char *name, char **p, const char *value, UnitWriteFlags flags);
int varlink_apply_string_escaped(Unit *u, const char *name, char **p, const char *value, UnitWriteFlags flags);
int varlink_apply_absolute_path(Unit *u, const char *name, char **p, const char *value, UnitWriteFlags flags);
int varlink_apply_uint64_limit(Unit *u, const char *name, uint64_t *p, uint64_t value, uint64_t minimum, UnitWriteFlags flags);

/* Nonnegative enum values must have a string representation, as guaranteed by their dispatchers.
 * The plain enum setters always return 0 for compatibility with property apply callbacks. */
#define DEFINE_VARLINK_APPLY_ENUM(prefix, type, to_string_fn)          \
        int varlink_apply_##prefix(                                    \
                        Unit *u,                                       \
                        const char *name,                              \
                        type *p,                                       \
                        type value,                                    \
                        UnitWriteFlags flags) {                        \
                assert(u);                                             \
                assert(name);                                          \
                assert(p);                                             \
                                                                       \
                if (value < 0)                                         \
                        return 0;                                      \
                                                                       \
                *p = value;                                            \
                const char *s = ASSERT_PTR((to_string_fn)(value));     \
                unit_write_settingf(u, flags, name, "%s=%s", name, s); \
                return 0;                                              \
        }

#define DEFINE_VARLINK_APPLY_ENUM_REFUSE(prefix, type, to_string_fn)                            \
        int varlink_apply_##prefix(                                                             \
                        Unit *u,                                                                \
                        const char *name,                                                       \
                        type *p,                                                                \
                        type value,                                                             \
                        bool (*refuse)(type),                                                   \
                        UnitWriteFlags flags) {                                                 \
                assert(u);                                                                      \
                assert(name);                                                                   \
                assert(p);                                                                      \
                assert(refuse);                                                                 \
                                                                                                \
                if (value < 0)                                                                  \
                        return 0;                                                               \
                if (refuse(value))                                                              \
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),                         \
                                               "%s=%s is not supported via Varlink.",           \
                                               name, ASSERT_PTR((to_string_fn)(value)));        \
                                                                                                \
                *p = value;                                                                     \
                const char *s = ASSERT_PTR((to_string_fn)(value));                              \
                unit_write_settingf(u, flags, name, "%s=%s", name, s);                          \
                return 0;                                                                       \
        }
