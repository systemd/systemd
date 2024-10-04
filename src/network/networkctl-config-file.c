/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-daemon.h"
#include "sd-device.h"
#include "sd-netlink.h"
#include "sd-network.h"

#include "bus-error.h"
#include "bus-locator.h"
#include "bus-util.h"
#include "bus-wait-for-jobs.h"
#include "conf-files.h"
#include "edit-util.h"
#include "mkdir-label.h"
#include "netlink-util.h"
#include "network-util.h"
#include "networkctl.h"
#include "networkctl-config-file.h"
#include "networkctl-util.h"
#include "pager.h"
#include "path-lookup.h"
#include "path-util.h"
#include "pretty-print.h"
#include "selinux-util.h"
#include "string-table.h"
#include "strv.h"
#include "virt.h"

typedef enum ReloadFlags {
        RELOAD_NETWORKD = 1 << 0,
        RELOAD_UDEVD    = 1 << 1,
} ReloadFlags;

typedef enum LinkConfigType {
        CONFIG_NETWORK,
        CONFIG_LINK,
        CONFIG_NETDEV,
        _CONFIG_MAX,
        _CONFIG_INVALID = -EINVAL,
} LinkConfigType;

static const char* const link_config_type_table[_CONFIG_MAX] = {
        [CONFIG_NETWORK] = "network",
        [CONFIG_LINK]    = "link",
        [CONFIG_NETDEV]  = "netdev",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING(link_config_type, LinkConfigType);

static int get_config_files_by_name(
                const char *name,
                bool allow_masked,
                char **ret_path,
                char ***ret_dropins) {

        _cleanup_free_ char *path = NULL;
        int r;

        assert(name);
        assert(ret_path);

        STRV_FOREACH(i, NETWORK_DIRS) {
                _cleanup_free_ char *p = NULL;

                p = path_join(*i, name);
                if (!p)
                        return -ENOMEM;

                r = RET_NERRNO(access(p, F_OK));
                if (r >= 0) {
                        if (!allow_masked) {
                                r = null_or_empty_path(p);
                                if (r < 0)
                                        return log_debug_errno(r,
                                                               "Failed to check if network config '%s' is masked: %m",
                                                               name);
                                if (r > 0)
                                        return -ERFKILL;
                        }

                        path = TAKE_PTR(p);
                        break;
                }

                if (r != -ENOENT)
                        log_debug_errno(r, "Failed to determine whether '%s' exists, ignoring: %m", p);
        }

        if (!path)
                return -ENOENT;

        if (ret_dropins) {
                _cleanup_free_ char *dropin_dirname = NULL;

                dropin_dirname = strjoin(name, ".d");
                if (!dropin_dirname)
                        return -ENOMEM;

                r = conf_files_list_dropins(ret_dropins, dropin_dirname, /* root = */ NULL, NETWORK_DIRS);
                if (r < 0)
                        return r;
        }

        *ret_path = TAKE_PTR(path);

        return 0;
}

static int get_dropin_by_name(
                const char *name,
                char * const *dropins,
                char **ret) {

        assert(name);
        assert(ret);

        STRV_FOREACH(i, dropins)
                if (path_equal_filename(*i, name)) {
                        _cleanup_free_ char *d = NULL;

                        d = strdup(*i);
                        if (!d)
                                return -ENOMEM;

                        *ret = TAKE_PTR(d);
                        return 1;
                }

        *ret = NULL;
        return 0;
}

static int get_network_files_by_link(
                const char *link,
                int ifindex,
                bool ignore_missing,
                char **ret_path,
                char ***ret_dropins) {

        _cleanup_strv_free_ char **dropins = NULL;
        _cleanup_free_ char *path = NULL;
        int r;

        assert(link);
        assert(ifindex > 0);
        assert(ret_path);
        assert(ret_dropins);

        r = sd_network_link_get_network_file(ifindex, &path);
        if (r == -ENODATA)
                return log_full_errno(ignore_missing ? LOG_DEBUG : LOG_ERR, SYNTHETIC_ERRNO(ENOENT),
                                      "Link '%s' has no associated network file.", link);
        if (r < 0)
                return log_error_errno(r, "Failed to get network file for link '%s': %m", link);

        r = sd_network_link_get_network_file_dropins(ifindex, &dropins);
        if (r < 0 && r != -ENODATA)
                return log_error_errno(r, "Failed to get network drop-ins for link '%s': %m", link);

        *ret_path = TAKE_PTR(path);
        *ret_dropins = TAKE_PTR(dropins);

        return 0;
}

static int get_netdev_files_by_link(
                const char *link,
                int ifindex,
                bool ignore_missing,
                char **ret_path,
                char ***ret_dropins) {

        _cleanup_strv_free_ char **dropins = NULL;
        _cleanup_free_ char *path = NULL;
        int r;

        assert(link);
        assert(ifindex > 0);
        assert(ret_path);
        assert(ret_dropins);

        r = sd_network_link_get_netdev_file(ifindex, &path);
        if (r == -ENODATA)
                return log_full_errno(ignore_missing ? LOG_DEBUG : LOG_ERR, SYNTHETIC_ERRNO(ENOENT),
                                      "Link '%s' has no associated netdev file.", link);
        if (r < 0)
                return log_error_errno(r, "Failed to get netdev file for link '%s': %m", link);

        r = sd_network_link_get_netdev_file_dropins(ifindex, &dropins);
        if (r < 0 && r != -ENODATA)
                return log_error_errno(r, "Failed to get netdev drop-ins for link '%s': %m", link);

        *ret_path = TAKE_PTR(path);
        *ret_dropins = TAKE_PTR(dropins);

        return 0;
}

static int get_link_files_by_link(const char *link, bool ignore_missing, char **ret_path, char ***ret_dropins) {
        _cleanup_(sd_device_unrefp) sd_device *device = NULL;
        _cleanup_strv_free_ char **dropins_split = NULL;
        _cleanup_free_ char *p = NULL;
        const char *path, *dropins;
        int r;

        assert(link);
        assert(ret_path);
        assert(ret_dropins);

        r = sd_device_new_from_ifname(&device, link);
        if (r < 0)
                return log_error_errno(r, "Failed to create sd-device object for link '%s': %m", link);

        r = sd_device_get_property_value(device, "ID_NET_LINK_FILE", &path);
        if (r == -ENOENT)
                return log_full_errno(ignore_missing ? LOG_DEBUG : LOG_ERR, r,
                                      "Link '%s' has no associated link file.", link);
        if (r < 0)
                return log_error_errno(r, "Failed to get link file for link '%s': %m", link);

        r = sd_device_get_property_value(device, "ID_NET_LINK_FILE_DROPINS", &dropins);
        if (r < 0 && r != -ENOENT)
                return log_error_errno(r, "Failed to get link drop-ins for link '%s': %m", link);
        if (r >= 0) {
                r = strv_split_full(&dropins_split, dropins, ":", EXTRACT_CUNESCAPE);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse link drop-ins for link '%s': %m", link);
        }

        p = strdup(path);
        if (!p)
                return log_oom();

        *ret_path = TAKE_PTR(p);
        *ret_dropins = TAKE_PTR(dropins_split);

        return 0;
}

static int get_config_files_by_link_config(
                const char *ifname,
                LinkConfigType type,
                bool ignore_missing,
                sd_netlink **rtnl,
                char **ret_path,
                char ***ret_dropins) {

        int r;

        assert(ifname);
        assert(type >= 0 && type < _CONFIG_MAX);
        assert(rtnl);
        assert(ret_path);
        assert(ret_dropins);

        if (type == CONFIG_LINK)
                return get_link_files_by_link(ifname, ignore_missing, ret_path, ret_dropins);

        if (!networkd_is_running())
                return log_full_errno(ignore_missing ? LOG_DEBUG : LOG_ERR, SYNTHETIC_ERRNO(ESRCH),
                                      "Cannot get network/netdev file for link if systemd-networkd is not running.");

        int ifindex = rtnl_resolve_interface_or_warn(rtnl, ifname);
        if (ifindex < 0)
                return ifindex;

        if (type == CONFIG_NETWORK)
                r = get_network_files_by_link(ifname, ifindex, ignore_missing, ret_path, ret_dropins);
        else if (type == CONFIG_NETDEV)
                r = get_netdev_files_by_link(ifname, ifindex, ignore_missing, ret_path, ret_dropins);
        else
                assert_not_reached();

        return r;
}

static int parse_link_config(const char *link_config, char **ret_ifname, LinkConfigType *ret_type) {
        const char *p = ASSERT_PTR(link_config);
        _cleanup_free_ char *ifname = NULL;
        int r;

        assert(ret_ifname);
        assert(ret_type);

        r = extract_first_word(&p, &ifname, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
        if (r <= 0)
                return log_error_errno(r < 0 ? r : SYNTHETIC_ERRNO(EINVAL),
                                       "Failed to extract link name from '%s': %m", link_config);

        if (!ifname_valid_full(ifname, IFNAME_VALID_ALTERNATIVE | IFNAME_VALID_NUMERIC))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid link name: %s", ifname);

        LinkConfigType t;

        if (isempty(p))
                t = CONFIG_NETWORK;
        else if (streq(p, "all"))
                t = _CONFIG_MAX;
        else {
                t = link_config_type_from_string(p);
                if (t < 0)
                        return log_error_errno(t, "Invalid config type '%s' for link '%s'.", p, ifname);
        }

        *ret_ifname = TAKE_PTR(ifname);
        *ret_type = t;

        return 0;
}

static int add_config_to_edit(
                EditFileContext *context,
                const char *path,
                char * const *dropins) {

        _cleanup_free_ char *new_path = NULL, *dropin_path = NULL, *old_dropin = NULL;
        _cleanup_strv_free_ char **comment_paths = NULL;
        int r;

        assert(context);
        assert(path);

        /* If we're supposed to edit main config file in /run/, but a config with the same name is present
         * under /etc/, we bail out since the one in /etc/ always overrides that in /run/. */
        if (arg_runtime && !arg_drop_in && path_startswith(path, "/etc"))
                return log_error_errno(SYNTHETIC_ERRNO(EEXIST),
                                       "Cannot edit runtime config file: overridden by %s", path);

        if (path_startswith(path, "/usr") || arg_runtime != !!path_startswith(path, "/run")) {
                _cleanup_free_ char *name = NULL;

                r = path_extract_filename(path, &name);
                if (r < 0)
                        return log_error_errno(r, "Failed to extract filename from '%s': %m", path);

                new_path = path_join(NETWORK_DIRS[arg_runtime ? 1 : 0], name);
                if (!new_path)
                        return log_oom();
        }

        if (!arg_drop_in)
                return edit_files_add(context, new_path ?: path, path, NULL);

        bool need_new_dropin;

        r = get_dropin_by_name(arg_drop_in, dropins, &old_dropin);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire drop-in '%s': %m", arg_drop_in);
        if (r > 0) {
                /* See the explanation above */
                if (arg_runtime && path_startswith(old_dropin, "/etc"))
                        return log_error_errno(SYNTHETIC_ERRNO(EEXIST),
                                               "Cannot edit runtime config file: overridden by %s", old_dropin);

                need_new_dropin = path_startswith(old_dropin, "/usr") || arg_runtime != !!path_startswith(old_dropin, "/run");
        } else
                need_new_dropin = true;

        if (!need_new_dropin)
                /* An existing drop-in is found in the correct scope. Let's edit it directly. */
                dropin_path = TAKE_PTR(old_dropin);
        else {
                /* No drop-in was found or an existing drop-in is in a different scope. Let's create a new
                 * drop-in file. */
                dropin_path = strjoin(new_path ?: path, ".d/", arg_drop_in);
                if (!dropin_path)
                        return log_oom();
        }

        comment_paths = strv_new(path);
        if (!comment_paths)
                return log_oom();

        r = strv_extend_strv(&comment_paths, dropins, /* filter_duplicates = */ false);
        if (r < 0)
                return log_oom();

        return edit_files_add(context, dropin_path, old_dropin, comment_paths);
}

static int udevd_reload(sd_bus *bus) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *w = NULL;
        const char *job_path;
        int r;

        assert(bus);

        r = bus_wait_for_jobs_new(bus, &w);
        if (r < 0)
                return log_error_errno(r, "Could not watch jobs: %m");

        r = bus_call_method(bus,
                            bus_systemd_mgr,
                            "ReloadUnit",
                            &error,
                            &reply,
                            "ss",
                            "systemd-udevd.service",
                            "replace");
        if (r < 0)
                return log_error_errno(r, "Failed to reload systemd-udevd: %s", bus_error_message(&error, r));

        r = sd_bus_message_read(reply, "o", &job_path);
        if (r < 0)
                return bus_log_parse_error(r);

        r = bus_wait_for_jobs_one(w, job_path, /* flags = */ 0, NULL);
        if (r == -ENOEXEC) {
                log_debug("systemd-udevd is not running, skipping reload.");
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to reload systemd-udevd: %m");

        return 1;
}

static int reload_daemons(ReloadFlags flags) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r, ret = 1;

        if (arg_no_reload)
                return 0;

        if (flags == 0)
                return 0;

        if (!sd_booted() || running_in_chroot() > 0) {
                log_debug("System is not booted with systemd or is running in chroot, skipping reload.");
                return 0;
        }

        r = sd_bus_open_system(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to system bus: %m");

        if (FLAGS_SET(flags, RELOAD_UDEVD))
                RET_GATHER(ret, udevd_reload(bus));

        if (FLAGS_SET(flags, RELOAD_NETWORKD)) {
                if (networkd_is_running()) {
                        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;

                        r = bus_call_method(bus, bus_network_mgr, "Reload", &error, NULL, NULL);
                        if (r < 0)
                                RET_GATHER(ret, log_error_errno(r, "Failed to reload systemd-networkd: %s", bus_error_message(&error, r)));
                } else
                        log_debug("systemd-networkd is not running, skipping reload.");
        }

        return ret;
}

int verb_edit(int argc, char *argv[], void *userdata) {
        char **args = ASSERT_PTR(strv_skip(argv, 1));
        _cleanup_(edit_file_context_done) EditFileContext context = {
                .marker_start = DROPIN_MARKER_START,
                .marker_end = DROPIN_MARKER_END,
                .remove_parent = !!arg_drop_in,
                .read_from_stdin = arg_stdin,
        };
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        ReloadFlags reload = 0;
        int r;

        if (!on_tty() && !arg_stdin)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Cannot edit network config files interactively if not on a tty.");

        /* Duplicating main configs makes no sense. This also mimics the behavior of systemctl. */
        if (arg_stdin && !arg_drop_in && strv_length(args) != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "When 'edit --stdin' without '--drop-in=', exactly one config file for editing must be specified.");

        r = mac_selinux_init();
        if (r < 0)
                return r;

        STRV_FOREACH(name, args) {
                _cleanup_strv_free_ char **dropins = NULL;
                _cleanup_free_ char *path = NULL;
                const char *link_config;

                link_config = startswith(*name, "@");
                if (link_config) {
                        _cleanup_free_ char *ifname = NULL;
                        LinkConfigType type;

                        r = parse_link_config(link_config, &ifname, &type);
                        if (r < 0)
                                return r;
                        if (type == _CONFIG_MAX)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                                       "Config type 'all' cannot be used with 'edit'.");

                        r = get_config_files_by_link_config(ifname, type,
                                                            /* ignore_missing = */ false,
                                                            &rtnl,
                                                            &path, &dropins);
                        if (r < 0)
                                return r;

                        r = add_config_to_edit(&context, path, dropins);
                        if (r < 0)
                                return r;

                        reload |= type == CONFIG_LINK ? RELOAD_UDEVD : RELOAD_NETWORKD;

                        continue;
                }

                if (ENDSWITH_SET(*name, ".network", ".netdev"))
                        reload |= RELOAD_NETWORKD;
                else if (endswith(*name, ".link"))
                        reload |= RELOAD_UDEVD;
                else
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid network config name '%s'.", *name);

                r = get_config_files_by_name(*name, /* allow_masked = */ false, &path, &dropins);
                if (r == -ERFKILL)
                        return log_error_errno(r, "Network config '%s' is masked.", *name);
                if (r == -ENOENT) {
                        if (arg_drop_in)
                                return log_error_errno(r, "Cannot find network config '%s'.", *name);

                        log_debug("No existing network config '%s' found, creating a new file.", *name);

                        path = path_join(NETWORK_DIRS[arg_runtime ? 1 : 0], *name);
                        if (!path)
                                return log_oom();

                        r = edit_files_add(&context, path, NULL, NULL);
                        if (r < 0)
                                return r;
                        continue;
                }
                if (r < 0)
                        return log_error_errno(r, "Failed to get the path of network config '%s': %m", *name);

                r = add_config_to_edit(&context, path, dropins);
                if (r < 0)
                        return r;
        }

        r = do_edit_files_and_install(&context);
        if (r < 0)
                return r;

        return reload_daemons(reload);
}

static int cat_files_by_link_one(
                const char *ifname,
                LinkConfigType type,
                sd_netlink **rtnl,
                bool ignore_missing,
                bool *first) {

        _cleanup_strv_free_ char **dropins = NULL;
        _cleanup_free_ char *path = NULL;
        int r;

        assert(ifname);
        assert(type >= 0 && type < _CONFIG_MAX);
        assert(rtnl);
        assert(first);

        r = get_config_files_by_link_config(ifname, type, ignore_missing, rtnl, &path, &dropins);
        if (ignore_missing && IN_SET(r, -ENOENT, -ESRCH))
                return 0;
        if (r < 0)
                return r;

        if (!*first)
                putchar('\n');

        r = cat_files(path, dropins, /* flags = */ CAT_FORMAT_HAS_SECTIONS);
        if (r < 0)
                return r;

        *first = false;

        return 0;
}

static int cat_files_by_link_config(const char *link_config, sd_netlink **rtnl, bool *first) {
        _cleanup_free_ char *ifname = NULL;
        LinkConfigType type;
        int r;

        assert(link_config);
        assert(rtnl);
        assert(first);

        r = parse_link_config(link_config, &ifname, &type);
        if (r < 0)
                return r;

        if (type == _CONFIG_MAX) {
                for (LinkConfigType i = 0; i < _CONFIG_MAX; i++) {
                        r = cat_files_by_link_one(ifname, i, rtnl, /* ignore_missing = */ true, first);
                        if (r < 0)
                                return r;
                }

                return 0;
        }

        return cat_files_by_link_one(ifname, type, rtnl, /* ignore_missing = */ false, first);
}

int verb_cat(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_netlink_unrefp) sd_netlink *rtnl = NULL;
        char **args = strv_skip(argv, 1);
        int r, ret = 0;

        pager_open(arg_pager_flags);

        if (strv_isempty(args))
                return conf_files_cat(NULL, "systemd/networkd.conf", CAT_FORMAT_HAS_SECTIONS);

        bool first = true;
        STRV_FOREACH(name, args) {
                const char *link_config;

                link_config = startswith(*name, "@");
                if (link_config) {
                        r = cat_files_by_link_config(link_config, &rtnl, &first);
                        if (r < 0)
                                return r;
                        continue;
                }

                _cleanup_strv_free_ char **dropins = NULL;
                _cleanup_free_ char *path = NULL;

                r = get_config_files_by_name(*name, /* allow_masked = */ false, &path, &dropins);
                if (r == -ENOENT) {
                        RET_GATHER(ret, log_error_errno(r, "Cannot find network config file '%s'.", *name));
                        continue;
                }
                if (r == -ERFKILL) {
                        RET_GATHER(ret, log_debug_errno(r, "Network config '%s' is masked, ignoring.", *name));
                        continue;
                }
                if (r < 0)
                        return log_error_errno(r, "Failed to get the path of network config '%s': %m", *name);

                if (!first)
                        putchar('\n');

                r = cat_files(path, dropins, /* flags = */ CAT_FORMAT_HAS_SECTIONS);
                if (r < 0)
                        return r;

                first = false;
        }

        return ret;
}

int verb_mask(int argc, char *argv[], void *userdata) {
        ReloadFlags flags = 0;
        int r;

        r = mac_selinux_init();
        if (r < 0)
                return r;

        STRV_FOREACH(name, strv_skip(argv, 1)) {
                _cleanup_free_ char *config_path = NULL, *symlink_path = NULL;
                ReloadFlags reload;

                /* We update the real 'flags' at last, since the operation can be skipped. */
                if (ENDSWITH_SET(*name, ".network", ".netdev"))
                        reload = RELOAD_NETWORKD;
                else if (endswith(*name, ".link"))
                        reload = RELOAD_UDEVD;
                else
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid network config name '%s'.", *name);

                r = get_config_files_by_name(*name, /* allow_masked = */ true, &config_path, /* ret_dropins = */ NULL);
                if (r == -ENOENT)
                        log_warning("No existing network config '%s' found, proceeding anyway.", *name);
                else if (r < 0)
                        return log_error_errno(r, "Failed to get the path of network config '%s': %m", *name);
                else if (!path_startswith(config_path, "/usr")) {
                        r = null_or_empty_path(config_path);
                        if (r < 0)
                                return log_error_errno(r,
                                                       "Failed to check if '%s' is masked: %m", config_path);
                        if (r > 0) {
                                log_debug("%s is already masked, skipping.", config_path);
                                continue;
                        }

                        /* At this point, we have found a config under mutable dir (/run/ or /etc/),
                         * so masking through /run/ (--runtime) is not possible. If it's under /etc/,
                         * then it doesn't work without --runtime either. */
                        if (arg_runtime || path_startswith(config_path, "/etc"))
                                return log_error_errno(SYNTHETIC_ERRNO(EEXIST),
                                                       "Cannot mask network config %s: %s exists",
                                                       *name, config_path);
                }

                symlink_path = path_join(NETWORK_DIRS[arg_runtime ? 1 : 0], *name);
                if (!symlink_path)
                        return log_oom();

                (void) mkdir_parents_label(symlink_path, 0755);

                if (symlink("/dev/null", symlink_path) < 0)
                        return log_error_errno(errno,
                                               "Failed to create symlink '%s' to /dev/null: %m", symlink_path);

                flags |= reload;
                log_info("Successfully created symlink '%s' to /dev/null.", symlink_path);
        }

        return reload_daemons(flags);
}

int verb_unmask(int argc, char *argv[], void *userdata) {
        ReloadFlags flags = 0;
        int r;

        STRV_FOREACH(name, strv_skip(argv, 1)) {
                _cleanup_free_ char *path = NULL;
                ReloadFlags reload;

                if (ENDSWITH_SET(*name, ".network", ".netdev"))
                        reload = RELOAD_NETWORKD;
                else if (endswith(*name, ".link"))
                        reload = RELOAD_UDEVD;
                else
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid network config name '%s'.", *name);

                r = get_config_files_by_name(*name, /* allow_masked = */ true, &path, /* ret_dropins = */ NULL);
                if (r == -ENOENT) {
                        log_debug_errno(r, "Network configuration '%s' doesn't exist, skipping.", *name);
                        continue;
                }
                if (r < 0)
                        return log_error_errno(r, "Failed to get the path of network config '%s': %m", *name);

                r = null_or_empty_path(path);
                if (r < 0)
                        return log_error_errno(r, "Failed to check if '%s' is masked: %m", path);
                if (r == 0)
                        continue;

                if (path_startswith(path, "/usr"))
                        return log_error_errno(r, "Cannot unmask network config under /usr/: %s", path);

                if (unlink(path) < 0) {
                        if (errno == ENOENT)
                                continue;

                        return log_error_errno(errno, "Failed to remove '%s': %m", path);
                }

                flags |= reload;
                log_info("Successfully removed masked network config '%s'.", path);
        }

        return reload_daemons(flags);
}
