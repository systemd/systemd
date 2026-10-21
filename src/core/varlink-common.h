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

/* If provided, *reterr_bad_field must be NULL or an owned heap string.
 * Array indexes in error field paths are currently not supported. */
void varlink_propagate_bad_field(const char *bad_field, const char *child_bad_field, char **reterr_bad_field);
int varlink_propagate_bad_field_errno(int errnum, const char *bad_field, const char *child_bad_field, char **reterr_bad_field);

/* For list settings where [] clears all previously configured entries. Preserve [] as an allocated empty
 * vector so apply helpers can distinguish that reset from null (NULL), which represents an absent setting. */
int varlink_dispatch_strv_preserve_empty(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata);

#define DEFINE_VARLINK_DISPATCH_SETTABLE(field, type, dispatch, ...)                       \
        int varlink_dispatch_settable_##field(                                             \
                        const char *name,                                                  \
                        sd_json_variant *variant,                                          \
                        sd_json_dispatch_flags_t flags,                                    \
                        void *userdata) {                                                  \
                type *p = ASSERT_PTR(userdata);                                            \
                int r;                                                                     \
                                                                                           \
                assert(name);                                                              \
                assert(variant);                                                           \
                                                                                           \
                if (sd_json_variant_is_null(variant)) {                                    \
                        p->field##_set = false;                                            \
                        return 0;                                                          \
                }                                                                          \
                                                                                           \
                r = (dispatch)(name, variant, flags, &p->field __VA_OPT__(,) __VA_ARGS__); \
                if (r >= 0)                                                                \
                        p->field##_set = true;                                             \
                                                                                           \
                return r;                                                                  \
        }

#define DEFINE_VARLINK_APPLY_SETTABLE(field, context_type, parameters_type, apply, ...)    \
        int varlink_apply_settable_##field(Unit *u, context_type *c, parameters_type *p) { \
                assert(p);                                                                 \
                                                                                           \
                if (!p->field##_set)                                                       \
                        return 0;                                                          \
                                                                                           \
                return (apply)(u, c, p->field __VA_OPT__(,) __VA_ARGS__);                  \
        }

/* Apply helpers return 0 for absent fields, 1 for applied settings (even if unchanged), or a negative error.
 * Negative tristates/enums and NULL strings represent absent fields. */
int varlink_apply_tristate_bool(Unit *u, const char *name, bool *p, int value, UnitWriteFlags flags);
int varlink_apply_string(Unit *u, const char *name, char **p, const char *value, UnitWriteFlags flags);
int varlink_apply_string_escaped(Unit *u, const char *name, char **p, const char *value, UnitWriteFlags flags);
int varlink_apply_absolute_path(Unit *u, const char *name, char **p, const char *value, UnitWriteFlags flags);

/* For list settings where null means absent and an empty list explicitly resets all configured entries.
 * Use with varlink_dispatch_strv_preserve_empty() so [] is not mistaken for an absent setting. */
int varlink_apply_strv(Unit *u, const char *name, char ***p, char **value, UnitWriteFlags flags);
int varlink_apply_strv_escaped(Unit *u, const char *name, char ***p, char **value, UnitWriteFlags flags);

int varlink_apply_uint64_limit(Unit *u, const char *name, uint64_t *p, uint64_t value, uint64_t minimum, UnitWriteFlags flags);

/* Takes a unit-file directive name; callers check field presence. Uses millisecond accuracy */
int varlink_apply_usec_per_msec(Unit *u, const char *name, usec_t *p, usec_t value, UnitWriteFlags flags);
/* Uses microsecond accuracy and serializes infinity as an empty assignment */
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
