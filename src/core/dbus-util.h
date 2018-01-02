/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include "sd-bus.h"
#include "unit.h"

#define BUS_DEFINE_SET_TRANSIENT(function, bus_type, type, cast_type, fmt) \
        int bus_set_transient_##function(                               \
                        Unit *u,                                        \
                        const char *name,                               \
                        cast_type *p,                                   \
                        sd_bus_message *message,                        \
                        UnitWriteFlags flags,                           \
                        sd_bus_error *error) {                          \
                                                                        \
                type v;                                                 \
                int r;                                                  \
                                                                        \
                assert(p);                                              \
                                                                        \
                r = sd_bus_message_read(message, bus_type, &v);         \
                if (r < 0)                                              \
                        return r;                                       \
                                                                        \
                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {                    \
                        *p = (cast_type) v;                             \
                        unit_write_settingf(u, flags, name,             \
                                            "%s=" fmt, name, v);        \
                }                                                       \
                                                                        \
                return 1;                                               \
        }                                                               \
        struct __useless_struct_to_allow_trailing_semicolon__

#define BUS_DEFINE_SET_TRANSIENT_IS_VALID(function, bus_type, type, cast_type, fmt, check) \
        int bus_set_transient_##function(                               \
                        Unit *u,                                        \
                        const char *name,                               \
                        cast_type *p,                                   \
                        sd_bus_message *message,                        \
                        UnitWriteFlags flags,                           \
                        sd_bus_error *error) {                          \
                                                                        \
                type v;                                                 \
                int r;                                                  \
                                                                        \
                assert(p);                                              \
                                                                        \
                r = sd_bus_message_read(message, bus_type, &v);         \
                if (r < 0)                                              \
                        return r;                                       \
                                                                        \
                if (!check(v))                                          \
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, \
                                                 "Invalid %s setting: " fmt, name, v); \
                                                                        \
                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {                    \
                        *p = (cast_type) v;                             \
                        unit_write_settingf(u, flags, name,             \
                                            "%s=" fmt, name, v);        \
                }                                                       \
                                                                        \
                return 1;                                               \
        }                                                               \
        struct __useless_struct_to_allow_trailing_semicolon__

#define BUS_DEFINE_SET_TRANSIENT_TO_STRING(function, bus_type, type, cast_type, fmt, to_string) \
        int bus_set_transient_##function(                               \
                        Unit *u,                                        \
                        const char *name,                               \
                        cast_type *p,                                   \
                        sd_bus_message *message,                        \
                        UnitWriteFlags flags,                           \
                        sd_bus_error *error) {                          \
                                                                        \
                const char *s;                                          \
                type v;                                                 \
                int r;                                                  \
                                                                        \
                assert(p);                                              \
                                                                        \
                r = sd_bus_message_read(message, bus_type, &v);         \
                if (r < 0)                                              \
                        return r;                                       \
                                                                        \
                s = to_string(v);                                       \
                if (!s)                                                 \
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, \
                                                 "Invalid %s setting: " fmt, name, v); \
                                                                        \
                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {                    \
                        *p = (cast_type) v;                             \
                        unit_write_settingf(u, flags, name,             \
                                            "%s=%s", name, s);          \
                }                                                       \
                                                                        \
                return 1;                                               \
        }                                                               \
        struct __useless_struct_to_allow_trailing_semicolon__

#define BUS_DEFINE_SET_TRANSIENT_TO_STRING_ALLOC(function, bus_type, type, cast_type, fmt, to_string) \
        int bus_set_transient_##function(                               \
                        Unit *u,                                        \
                        const char *name,                               \
                        cast_type *p,                                   \
                        sd_bus_message *message,                        \
                        UnitWriteFlags flags,                           \
                        sd_bus_error *error) {                          \
                                                                        \
                _cleanup_free_ char *s = NULL;                          \
                type v;                                                 \
                int r;                                                  \
                                                                        \
                assert(p);                                              \
                                                                        \
                r = sd_bus_message_read(message, bus_type, &v);         \
                if (r < 0)                                              \
                        return r;                                       \
                                                                        \
                r = to_string(v, &s);                                   \
                if (r == -EINVAL)                                       \
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, \
                                                 "Invalid %s setting: " fmt, name, v); \
                if (r < 0)                                              \
                        return r;                                       \
                                                                        \
                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {                    \
                        *p = (cast_type) v;                             \
                        unit_write_settingf(u, flags, name,             \
                                            "%s=%s", name, s);          \
                }                                                       \
                                                                        \
                return 1;                                               \
        }                                                               \
        struct __useless_struct_to_allow_trailing_semicolon__

#define BUS_DEFINE_SET_TRANSIENT_PARSE(function, type, parse)           \
        int bus_set_transient_##function(                               \
                        Unit *u,                                        \
                        const char *name,                               \
                        type *p,                                        \
                        sd_bus_message *message,                        \
                        UnitWriteFlags flags,                           \
                        sd_bus_error *error) {                          \
                                                                        \
                const char *s;                                          \
                type v;                                                 \
                int r;                                                  \
                                                                        \
                assert(p);                                              \
                                                                        \
                r = sd_bus_message_read(message, "s", &s);              \
                if (r < 0)                                              \
                        return r;                                       \
                                                                        \
                v = parse(s);                                           \
                if (v < 0)                                              \
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, \
                                                 "Invalid %s setting: %s", name, s); \
                                                                        \
                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {                    \
                        *p = v;                                         \
                        unit_write_settingf(u, flags, name,             \
                                            "%s=%s", name, s);          \
                }                                                       \
                                                                        \
                return 1;                                               \
        }                                                               \
        struct __useless_struct_to_allow_trailing_semicolon__

#define BUS_DEFINE_SET_TRANSIENT_PARSE_PTR(function, type, parse)       \
        int bus_set_transient_##function(                               \
                        Unit *u,                                        \
                        const char *name,                               \
                        type *p,                                        \
                        sd_bus_message *message,                        \
                        UnitWriteFlags flags,                           \
                        sd_bus_error *error) {                          \
                                                                        \
                const char *s;                                          \
                type v;                                                 \
                int r;                                                  \
                                                                        \
                assert(p);                                              \
                                                                        \
                r = sd_bus_message_read(message, "s", &s);              \
                if (r < 0)                                              \
                        return r;                                       \
                                                                        \
                r = parse(s, &v);                                       \
                if (r < 0)                                              \
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, \
                                                 "Invalid %s setting: %s", name, s); \
                                                                        \
                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {                    \
                        *p = v;                                         \
                        unit_write_settingf(u, flags, name,             \
                                            "%s=%s", name, strempty(s)); \
                }                                                       \
                                                                        \
                return 1;                                               \
        }                                                               \
        struct __useless_struct_to_allow_trailing_semicolon__

#define BUS_DEFINE_SET_TRANSIENT_STRING_WITH_CHECK(function, check)     \
        int bus_set_transient_##function(                               \
                        Unit *u,                                        \
                        const char *name,                               \
                        char **p,                                       \
                        sd_bus_message *message,                        \
                        UnitWriteFlags flags,                           \
                        sd_bus_error *error) {                          \
                                                                        \
                const char *v;                                          \
                int r;                                                  \
                                                                        \
                assert(p);                                              \
                                                                        \
                r = sd_bus_message_read(message, "s", &v);              \
                if (r < 0)                                              \
                        return r;                                       \
                                                                        \
                if (!isempty(v) && !check(v))                           \
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, \
                                                 "Invalid %s setting: %s", name, v); \
                                                                        \
                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {                    \
                        r = free_and_strdup(p, empty_to_null(v));       \
                        if (r < 0)                                      \
                                return r;                               \
                                                                        \
                        unit_write_settingf(u, flags|UNIT_ESCAPE_SPECIFIERS, name, \
                                            "%s=%s", name, strempty(v)); \
                }                                                       \
                                                                        \
                return 1;                                               \
        }                                                               \
        struct __useless_struct_to_allow_trailing_semicolon__

#define BUS_DEFINE_SET_CGROUP_WEIGHT(function, mask, check, val, str)   \
        int bus_cgroup_set_##function(                                  \
                        Unit *u,                                        \
                        const char *name,                               \
                        uint64_t *p,                                    \
                        sd_bus_message *message,                        \
                        UnitWriteFlags flags,                           \
                        sd_bus_error *error) {                          \
                                                                        \
                uint64_t v;                                             \
                int r;                                                  \
                                                                        \
                assert(p);                                              \
                                                                        \
                r = sd_bus_message_read(message, "t", &v);              \
                if (r < 0)                                              \
                        return r;                                       \
                                                                        \
                if (!check(v))                                          \
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, \
                                                 "Value specified in %s is out of range", name); \
                                                                        \
                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {                    \
                        *p = v;                                         \
                        unit_invalidate_cgroup(u, (mask));              \
                                                                        \
                        if (v == (val))                                 \
                                unit_write_settingf(u, flags, name,     \
                                                    "%s=" str, name);   \
                        else                                            \
                                unit_write_settingf(u, flags, name,     \
                                                    "%s=%" PRIu64, name, v); \
                }                                                       \
                                                                        \
                return 1;                                               \
        }                                                               \
        struct __useless_struct_to_allow_trailing_semicolon__

#define BUS_DEFINE_SET_CGROUP_SCALE(function, mask, scale)              \
        int bus_cgroup_set_##function##_scale(                          \
                        Unit *u,                                        \
                        const char *name,                               \
                        uint64_t *p,                                    \
                        sd_bus_message *message,                        \
                        UnitWriteFlags flags,                           \
                        sd_bus_error *error) {                          \
                                                                        \
                uint64_t v;                                             \
                uint32_t raw;                                           \
                int r;                                                  \
                                                                        \
                assert(p);                                              \
                                                                        \
                r = sd_bus_message_read(message, "u", &raw);            \
                if (r < 0)                                              \
                        return r;                                       \
                                                                        \
                v = scale(raw, UINT32_MAX);                             \
                if (v <= 0 || v >= UINT64_MAX)                          \
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, \
                                                 "Value specified in %s is out of range", name); \
                                                                        \
                if (!UNIT_WRITE_FLAGS_NOOP(flags)) {                    \
                        const char *e;                                  \
                                                                        \
                        *p = v;                                         \
                        unit_invalidate_cgroup(u, (mask));              \
                                                                        \
                        /* Chop off suffix */                           \
                        assert_se(e = endswith(name, "Scale"));         \
                        name = strndupa(name, e - name);                \
                                                                        \
                        unit_write_settingf(u, flags, name, "%s=%" PRIu32 "%%", name, \
                                            (uint32_t) (DIV_ROUND_UP((uint64_t) raw * 100U, (uint64_t) UINT32_MAX))); \
                }                                                       \
                                                                        \
                return 1;                                               \
        }                                                               \
        struct __useless_struct_to_allow_trailing_semicolon__

int bus_set_transient_mode_t(Unit *u, const char *name, mode_t *p, sd_bus_message *message, UnitWriteFlags flags, sd_bus_error *error);
int bus_set_transient_unsigned(Unit *u, const char *name, unsigned *p, sd_bus_message *message, UnitWriteFlags flags, sd_bus_error *error);
int bus_set_transient_user(Unit *u, const char *name, char **p, sd_bus_message *message, UnitWriteFlags flags, sd_bus_error *error);
int bus_set_transient_path(Unit *u, const char *name, char **p, sd_bus_message *message, UnitWriteFlags flags, sd_bus_error *error);
int bus_set_transient_string(Unit *u, const char *name, char **p, sd_bus_message *message, UnitWriteFlags flags, sd_bus_error *error);
int bus_set_transient_bool(Unit *u, const char *name, bool *p, sd_bus_message *message, UnitWriteFlags flags, sd_bus_error *error);
int bus_set_transient_usec_internal(Unit *u, const char *name, usec_t *p, bool fix_0, sd_bus_message *message, UnitWriteFlags flags, sd_bus_error *error);
static inline int bus_set_transient_usec(Unit *u, const char *name, usec_t *p, sd_bus_message *message, UnitWriteFlags flags, sd_bus_error *error) {
        return bus_set_transient_usec_internal(u, name, p, false, message, flags, error);
}
static inline int bus_set_transient_usec_fix_0(Unit *u, const char *name, usec_t *p, sd_bus_message *message, UnitWriteFlags flags, sd_bus_error *error) {
        return bus_set_transient_usec_internal(u, name, p, true, message, flags, error);
}
