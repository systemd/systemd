/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-polkit.h"
#include "bus-util.h"
#include "dbus-util.h"
#include "escape.h"
#include "parse-util.h"
#include "path-util.h"
#include "unit-printf.h"
#include "user-util.h"
#include "unit.h"

int bus_property_get_triggered_unit(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Unit *u = userdata, *trigger;

        assert(bus);
        assert(reply);
        assert(u);

        trigger = UNIT_TRIGGER(u);

        return sd_bus_message_append(reply, "s", trigger ? trigger->id : NULL);
}

BUS_DEFINE_SET_TRANSIENT(mode_t, "u", uint32_t, mode_t, "%04o");
BUS_DEFINE_SET_TRANSIENT(unsigned, "u", uint32_t, unsigned, "%" PRIu32);

static bool valid_user_group_name_or_id_relaxed(const char *u) {
        return valid_user_group_name(u, VALID_USER_ALLOW_NUMERIC|VALID_USER_RELAX);
}

BUS_DEFINE_SET_TRANSIENT_STRING_WITH_CHECK(user_relaxed, valid_user_group_name_or_id_relaxed);
BUS_DEFINE_SET_TRANSIENT_STRING_WITH_CHECK(path, path_is_absolute);

int bus_set_transient_string(
                Unit *u,
                const char *name,
                char **p,
                sd_bus_message *message,
                UnitWriteFlags flags,
                sd_bus_error *error) {

        const char *v;
        int r;

        assert(p);

        r = sd_bus_message_read(message, "s", &v);
        if (r < 0)
                return r;

        if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                r = free_and_strdup(p, empty_to_null(v));
                if (r < 0)
                        return r;

                unit_write_settingf(u, flags|UNIT_ESCAPE_SPECIFIERS, name,
                                    "%s=%s", name, strempty(v));
        }

        return 1;
}

int bus_set_transient_bool(
                Unit *u,
                const char *name,
                bool *p,
                sd_bus_message *message,
                UnitWriteFlags flags,
                sd_bus_error *error) {

        int v, r;

        assert(p);

        r = sd_bus_message_read(message, "b", &v);
        if (r < 0)
                return r;

        if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                *p = v;
                unit_write_settingf(u, flags, name, "%s=%s", name, yes_no(v));
        }

        return 1;
}

int bus_set_transient_tristate(
                Unit *u,
                const char *name,
                int *p,
                sd_bus_message *message,
                UnitWriteFlags flags,
                sd_bus_error *error) {

        int v, r;

        assert(p);

        r = sd_bus_message_read(message, "b", &v);
        if (r < 0)
                return r;

        if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                *p = v;
                unit_write_settingf(u, flags, name, "%s=%s", name, yes_no(v));
        }

        return 1;
}

int bus_set_transient_usec_internal(
                Unit *u,
                const char *name,
                usec_t *p,
                bool fix_0,
                sd_bus_message *message,
                UnitWriteFlags flags,
                sd_bus_error *error) {

        uint64_t v;
        int r;

        assert(p);

        r = sd_bus_message_read(message, "t", &v);
        if (r < 0)
                return r;

        if (!UNIT_WRITE_FLAGS_NOOP(flags)) {
                if (fix_0)
                        *p = v != 0 ? v: USEC_INFINITY;
                else
                        *p = v;

                char *n = strndupa_safe(name, strlen(name) - 4);
                unit_write_settingf(u, flags, name, "%sSec=%s", n, FORMAT_TIMESPAN(v, USEC_PER_MSEC));
        }

        return 1;
}

int bus_verify_manage_units_async_full(
                Unit *u,
                const char *verb,
                const char *polkit_message,
                sd_bus_message *call,
                sd_bus_error *error) {

        const char *details[9] = {
                "unit", u->id,
                "verb", verb,
        };

        if (polkit_message) {
                details[4] = "polkit.message";
                details[5] = polkit_message;
                details[6] = "polkit.gettext_domain";
                details[7] = GETTEXT_PACKAGE;
        }

        return bus_verify_polkit_async(
                        call,
                        "org.freedesktop.systemd1.manage-units",
                        details,
                        &u->manager->polkit_registry,
                        error);
}

/* ret_format_str is an accumulator, so if it has any pre-existing content, new options will be appended to it */
int bus_read_mount_options(
                sd_bus_message *message,
                sd_bus_error *error,
                MountOptions **ret_options,
                char **ret_format_str,
                const char *separator) {

        _cleanup_(mount_options_free_allp) MountOptions *options = NULL;
        _cleanup_free_ char *format_str = NULL;
        const char *mount_options, *partition;
        int r;

        assert(message);
        assert(ret_options);
        assert(separator);

        r = sd_bus_message_enter_container(message, 'a', "(ss)");
        if (r < 0)
                return r;

        while ((r = sd_bus_message_read(message, "(ss)", &partition, &mount_options)) > 0) {
                _cleanup_free_ char *escaped = NULL;
                _cleanup_free_ MountOptions *o = NULL;
                PartitionDesignator partition_designator;

                if (chars_intersect(mount_options, WHITESPACE))
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                                "Invalid mount options string, contains whitespace character(s): %s", mount_options);

                partition_designator = partition_designator_from_string(partition);
                if (partition_designator < 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid partition name %s", partition);

                /* Need to store the options with the escapes, so that they can be parsed again */
                escaped = shell_escape(mount_options, ":");
                if (!escaped)
                        return -ENOMEM;

                if (!strextend_with_separator(&format_str, separator, partition, ":", escaped))
                        return -ENOMEM;

                o = new(MountOptions, 1);
                if (!o)
                        return -ENOMEM;
                *o = (MountOptions) {
                        .partition_designator = partition_designator,
                        .options = strdup(mount_options),
                };
                if (!o->options)
                        return -ENOMEM;
                LIST_APPEND(mount_options, options, TAKE_PTR(o));
        }
        if (r < 0)
                return r;

        r = sd_bus_message_exit_container(message);
        if (r < 0)
                return r;

        if (options) {
                if (ret_format_str) {
                        char *final = strjoin(*ret_format_str, !isempty(*ret_format_str) ? separator : "", format_str);
                        if (!final)
                                return -ENOMEM;
                        free_and_replace(*ret_format_str, final);
                }
                LIST_JOIN(mount_options, *ret_options, options);
        }

        return 0;
}

int bus_property_get_activation_details(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        ActivationDetails **details = ASSERT_PTR(userdata);
        _cleanup_strv_free_ char **pairs = NULL;
        int r;

        assert(reply);

        r = activation_details_append_pair(*details, &pairs);
        if (r < 0)
                return r;

        r = sd_bus_message_open_container(reply, 'a', "(ss)");
        if (r < 0)
                return r;

        STRV_FOREACH_PAIR(key, value, pairs) {
                r = sd_bus_message_append(reply, "(ss)", *key, *value);
                if (r < 0)
                        return r;
        }

        return sd_bus_message_close_container(reply);
}
