/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <errno.h>

#include "alloc-util.h"
#include "bus-error.h"
#include "bus-util.h"
#include "chase.h"
#include "conf-files.h"
#include "constants.h"
#include "device-private.h"
#include "path-util.h"
#include "udev-ctrl.h"
#include "udev-varlink.h"
#include "udevadm-util.h"
#include "unit-name.h"
#include "varlink-util.h"

static int find_device_from_unit(const char *unit_name, sd_device **ret) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_free_ char *unit_path = NULL, *syspath = NULL;
        int r;

        if (!unit_name_is_valid(unit_name, UNIT_NAME_PLAIN))
                return -EINVAL;

        if (unit_name_to_type(unit_name) != UNIT_DEVICE)
                return -EINVAL;

        r = bus_connect_system_systemd(&bus);
        if (r < 0) {
                _cleanup_free_ char *path = NULL;

                log_debug_errno(r, "Failed to open connection to systemd, using unit name as syspath: %m");

                r = unit_name_to_path(unit_name, &path);
                if (r < 0)
                        return log_debug_errno(r, "Failed to convert \"%s\" to a device path: %m", unit_name);

                return sd_device_new_from_path(ret, path);
        }

        unit_path = unit_dbus_path_from_name(unit_name);
        if (!unit_path)
                return -ENOMEM;

        r = sd_bus_get_property_string(
                        bus,
                        "org.freedesktop.systemd1",
                        unit_path,
                        "org.freedesktop.systemd1.Device",
                        "SysFSPath",
                        &error,
                        &syspath);
        if (r < 0)
                return log_debug_errno(r, "Failed to get SysFSPath= dbus property for %s: %s",
                                       unit_name, bus_error_message(&error, r));

        return sd_device_new_from_syspath(ret, syspath);
}

int find_device(const char *id, const char *prefix, sd_device **ret) {
        assert(id);
        assert(ret);

        if (sd_device_new_from_path(ret, id) >= 0)
                return 0;

        if (prefix && !path_startswith(id, prefix)) {
                _cleanup_free_ char *path = NULL;

                path = path_join(prefix, id);
                if (!path)
                        return -ENOMEM;

                if (sd_device_new_from_path(ret, path) >= 0)
                        return 0;
        }

        /* if a path is provided, then it cannot be a unit name. Let's return earlier. */
        if (is_path(id))
                return -ENODEV;

        /* Check if the argument looks like a device unit name. */
        return find_device_from_unit(id, ret);
}

int find_device_with_action(const char *id, sd_device_action_t action, sd_device **ret) {
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        int r;

        assert(id);
        assert(ret);
        assert(action >= 0 && action < _SD_DEVICE_ACTION_MAX);

        r = find_device(id, "/sys", &dev);
        if (r < 0)
                return r;

        r = device_read_uevent_file(dev);
        if (r < 0)
                return r;

        r = device_set_action(dev, action);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(dev);
        return 0;
}

int parse_device_action(const char *str, sd_device_action_t *action) {
        sd_device_action_t a;

        assert(str);
        assert(action);

        if (streq(str, "help")) {
                dump_device_action_table();
                return 0;
        }

        a = device_action_from_string(str);
        if (a < 0)
                return a;

        *action = a;
        return 1;
}

static int udev_ping_via_ctrl(usec_t timeout_usec, bool ignore_connection_failure) {
        _cleanup_(udev_ctrl_unrefp) UdevCtrl *uctrl = NULL;
        int r;

        r = udev_ctrl_new(&uctrl);
        if (r < 0)
                return log_error_errno(r, "Failed to initialize udev control: %m");

        r = udev_ctrl_send_ping(uctrl);
        if (r < 0) {
                bool ignore = ignore_connection_failure && (ERRNO_IS_NEG_DISCONNECT(r) || r == -ENOENT);
                log_full_errno(ignore ? LOG_DEBUG : LOG_ERR, r,
                               "Failed to connect to udev daemon%s: %m",
                               ignore ? ", ignoring" : "");
                return ignore ? 0 : r;
        }

        r = udev_ctrl_wait(uctrl, timeout_usec);
        if (r < 0)
                return log_error_errno(r, "Failed to wait for daemon to reply: %m");

        return 1; /* received reply */
}

int udev_ping(usec_t timeout_usec, bool ignore_connection_failure) {
        _cleanup_(sd_varlink_flush_close_unrefp) sd_varlink *link = NULL;
        int r;

        r = udev_varlink_connect(&link, timeout_usec);
        if (ERRNO_IS_NEG_DISCONNECT(r) || r == -ENOENT) {
                log_debug_errno(r, "Failed to connect to udev via varlink, falling back to use legacy control socket, ignoring: %m");
                return udev_ping_via_ctrl(timeout_usec, ignore_connection_failure);
        }
        if (r < 0)
                return log_error_errno(r, "Failed to connect to udev via varlink: %m");

        r = varlink_call_and_log(link, "io.systemd.service.Ping", /* parameters = */ NULL, /* reply = */ NULL);
        if (r < 0)
                return r;

        return 1; /* received reply */
}

static int search_rules_file_in_conf_dirs(const char *s, const char *root, char ***files) {
        _cleanup_free_ char *filename = NULL;
        int r;

        assert(s);

        if (!endswith(s, ".rules"))
                filename = strjoin(s, ".rules");
        else
                filename = strdup(s);
        if (!filename)
                return log_oom();

        if (!filename_is_valid(filename))
                return 0;

        STRV_FOREACH(p, CONF_PATHS_STRV("udev/rules.d")) {
                _cleanup_free_ char *path = NULL, *resolved = NULL;

                path = path_join(*p, filename);
                if (!path)
                        return log_oom();

                r = chase(path, root, CHASE_PREFIX_ROOT | CHASE_MUST_BE_REGULAR, &resolved, /* ret_fd = */ NULL);
                if (r == -ENOENT)
                        continue;
                if (r < 0)
                        return log_error_errno(r, "Failed to chase \"%s\": %m", path);

                r = strv_consume(files, TAKE_PTR(resolved));
                if (r < 0)
                        return log_oom();

                return 1; /* found */
        }

        return 0;
}

static int search_rules_file(const char *s, const char *root, char ***files) {
        int r;

        assert(s);
        assert(files);

        /* If the input is a file name (e.g. 99-systemd.rules), then try to find it in udev/rules.d directories. */
        r = search_rules_file_in_conf_dirs(s, root, files);
        if (r != 0)
                return r;

        /* If not found, or if it is a path, then chase it. */
        struct stat st;
        _cleanup_free_ char *resolved = NULL;
        r = chase_and_stat(s, root, CHASE_PREFIX_ROOT, &resolved, &st);
        if (r < 0)
                return log_error_errno(r, "Failed to chase \"%s\": %m", s);

        r = stat_verify_regular(&st);
        if (r == -EISDIR) {
                _cleanup_strv_free_ char **files_in_dir = NULL;

                r = conf_files_list_strv(&files_in_dir, ".rules", root, 0, (const char* const*) STRV_MAKE_CONST(s));
                if (r < 0)
                        return log_error_errno(r, "Failed to enumerate rules files in '%s': %m", resolved);

                r = strv_extend_strv_consume(files, TAKE_PTR(files_in_dir), /* filter_duplicates = */ false);
                if (r < 0)
                        return log_oom();

                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "'%s' is neither a regular file nor a directory: %m", resolved);

        r = strv_consume(files, TAKE_PTR(resolved));
        if (r < 0)
                return log_oom();

        return 0;
}

int search_rules_files(char * const *a, const char *root, char ***ret) {
        _cleanup_strv_free_ char **files = NULL;
        int r;

        assert(ret);

        if (strv_isempty(a)) {
                r = conf_files_list_strv(&files, ".rules", root, 0, (const char* const*) CONF_PATHS_STRV("udev/rules.d"));
                if (r < 0)
                        return log_error_errno(r, "Failed to enumerate rules files: %m");

                if (root && strv_isempty(files))
                        return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "No rules files found in %s.", root);

        } else
                STRV_FOREACH(s, a) {
                        r = search_rules_file(*s, root, &files);
                        if (r < 0)
                                return r;
                }

        *ret = TAKE_PTR(files);
        return 0;
}
