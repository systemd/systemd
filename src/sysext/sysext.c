/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/loop.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/mount.h>
#include <unistd.h>

#include "sd-json.h"
#include "sd-varlink.h"

#include "argv-util.h"
#include "blkid-util.h"
#include "blockdev-util.h"
#include "build.h"
#include "bus-common-errors.h"
#include "bus-locator.h"
#include "bus-polkit.h"
#include "bus-unit-util.h"
#include "bus-util.h"
#include "bus-wait-for-jobs.h"
#include "capability-util.h"
#include "chase.h"
#include "conf-parser.h"
#include "cryptsetup-util.h"
#include "devnum-util.h"
#include "discover-image.h"
#include "dissect-image.h"
#include "dlopen-note.h"
#include "env-util.h"
#include "errno-util.h"
#include "escape.h"
#include "extension-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-table.h"
#include "fs-util.h"
#include "fstab-util.h"
#include "hashmap.h"
#include "host-properties.h"
#include "image-policy.h"
#include "initrd-util.h"
#include "label-util.h"                 /* IWYU pragma: keep */
#include "libmount-util.h"
#include "log.h"
#include "loop-util.h"
#include "main-func.h"
#include "mkdir.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "os-util.h"
#include "pager.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "path-util.h"
#include "proc-cmdline.h"
#include "process-util.h"
#include "random-util.h"
#include "rm-rf.h"
#include "runtime-scope.h"
#include "selinux-util.h"
#include "set.h"
#include "socket-util.h"
#include "sort-util.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "unit-name.h"
#include "varlink-io.systemd.SysUpdate.Notify.h"
#include "varlink-io.systemd.sysext.h"
#include "varlink-util.h"
#include "verbs.h"
#include "xattr-match.h"

typedef enum MutableMode {
        MUTABLE_NO,
        MUTABLE_YES,
        MUTABLE_AUTO,
        MUTABLE_IMPORT,
        MUTABLE_EPHEMERAL,
        MUTABLE_EPHEMERAL_IMPORT,
        _MUTABLE_MAX,
        _MUTABLE_INVALID = -EINVAL,
} MutableMode;

static const char* const mutable_mode_table[_MUTABLE_MAX] = {
        [MUTABLE_NO]               = "no",
        [MUTABLE_YES]              = "yes",
        [MUTABLE_AUTO]             = "auto",
        [MUTABLE_IMPORT]           = "import",
        [MUTABLE_EPHEMERAL]        = "ephemeral",
        [MUTABLE_EPHEMERAL_IMPORT] = "ephemeral-import",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(mutable_mode, MutableMode, MUTABLE_YES);

enum {
        MERGE_NOTHING_FOUND,
        MERGE_MOUNTED,
        MERGE_SKIP_REFRESH,
};

static char *arg_root = NULL;
static sd_json_format_flags_t arg_json_format_flags = SD_JSON_FORMAT_OFF;
static PagerFlags arg_pager_flags = 0;
static bool arg_legend = true;
static bool arg_force = false;
static bool arg_no_reload = false;
static bool arg_always_refresh = false;
static int arg_noexec = -1;
static ImagePolicy *arg_image_policy = NULL;
static bool arg_image_policy_argv_set = false;
static bool arg_varlink = false;
static MutableMode arg_mutable = MUTABLE_NO;
static bool arg_mutable_argv_set = false;

/* Is set to IMAGE_CONFEXT when systemd is called with the confext functionality instead of the default */
static ImageClass arg_image_class = IMAGE_SYSEXT;

#define MUTABLE_EXTENSIONS_BASE_DIR "/var/lib/extensions.mutable"

/* redirect_dir=on and noatime prevent unnecessary upcopies, metacopy=off prevents broken
 * files from partial upcopies after umount, index=off allows reuse of the upper/work dirs */
#define MUTABLE_EXTENSIONS_MOUNT_OPTIONS "redirect_dir=on,noatime,metacopy=off,index=off"

STATIC_DESTRUCTOR_REGISTER(arg_root, freep);
STATIC_DESTRUCTOR_REGISTER(arg_image_policy, image_policy_freep);

COMMAND(
        "systemd-sysext\0",
        "Merge system extension images into /usr/ and /opt/.",
        .man_page = "systemd-sysext(8)",
        .flags = COMMAND_VERBS_SHARED,
        .pager_flags = &arg_pager_flags,
);
COMMAND(
        "systemd-confext\0",
        "Merge configuration extension images into /etc/.",
        .man_page = "systemd-confext(8)",
        .flags = COMMAND_VERBS_SHARED,
        .pager_flags = &arg_pager_flags,
);

/* Helper struct for naming simplicity and reusability */
static const struct {
        const char *short_identifier;
        const char *short_identifier_plural;
        const char *polkit_rw_action_id;
        const char *polkit_ro_action_id;
        const char *dot_directory_name;
        const char *directory_name;
        const char *level_env;
        const char *scope_env;
        const char *name_env;
        const char *mode_env;
        const char *opts_env;
        const char *beneath_env;
        const ImagePolicy *default_image_policy;
        unsigned long default_mount_flags;
} image_class_info[_IMAGE_CLASS_MAX] = {
        [IMAGE_SYSEXT] = {
                .short_identifier = "sysext",
                .short_identifier_plural = "extensions",
                .polkit_rw_action_id = "io.systemd.sysext.manage",
                .polkit_ro_action_id = "io.systemd.sysext.read",
                .dot_directory_name = ".systemd-sysext",
                .level_env = "SYSEXT_LEVEL",
                .scope_env = "SYSEXT_SCOPE",
                .name_env = "SYSTEMD_SYSEXT_HIERARCHIES",
                .mode_env = "SYSTEMD_SYSEXT_MUTABLE_MODE",
                .opts_env = "SYSTEMD_SYSEXT_OVERLAYFS_MOUNT_OPTIONS",
                .beneath_env = "SYSTEMD_SYSEXT_MOUNT_BENEATH",
                .default_image_policy = &image_policy_sysext,
                .default_mount_flags = MS_RDONLY|MS_NODEV,
        },
        [IMAGE_CONFEXT] = {
                .short_identifier = "confext",
                .short_identifier_plural = "confexts",
                .polkit_rw_action_id = "io.systemd.confext.manage",
                .polkit_ro_action_id = "io.systemd.confext.read",
                .dot_directory_name = ".systemd-confext",
                .level_env = "CONFEXT_LEVEL",
                .scope_env = "CONFEXT_SCOPE",
                .name_env = "SYSTEMD_CONFEXT_HIERARCHIES",
                .mode_env = "SYSTEMD_CONFEXT_MUTABLE_MODE",
                .opts_env = "SYSTEMD_CONFEXT_OVERLAYFS_MOUNT_OPTIONS",
                .beneath_env = "SYSTEMD_CONFEXT_MOUNT_BENEATH",
                .default_image_policy = &image_policy_confext,
                .default_mount_flags = MS_RDONLY|MS_NODEV|MS_NOSUID|MS_NOEXEC,
        }
};

static int parse_mutable_mode(const char *p) {
        return mutable_mode_from_string(p);
}

static DEFINE_CONFIG_PARSE_ENUM(config_parse_mutable_mode, mutable_mode, MutableMode);

typedef struct Context {
        ImageClass image_class;
        char **hierarchies;
        char *root;
        bool force;
        bool no_reload;
        bool always_refresh;
        int noexec;
        MutableMode mutable;
        bool mutable_set;
        ImagePolicy *image_policy;
        bool image_policy_set;
        /* image_policy is usually borrowed from arg_image_policy. When parsed from configuration, this
         * context owns it and frees it in context_done(). */
        bool image_policy_owned;
        const char *overlayfs_mount_options;
        bool mount_beneath;
} Context;

#define CONTEXT_NULL                            \
        (Context) {                             \
                .image_class = IMAGE_SYSEXT,    \
                .noexec = -1,                   \
                .mutable = MUTABLE_NO,          \
                .mount_beneath = true,          \
        }

static void context_done(Context *c) {
        assert(c);

        c->hierarchies = strv_free(c->hierarchies);
        c->root = mfree(c->root);

        if (c->image_policy_owned)
                c->image_policy = image_policy_free(c->image_policy);
}

static void parse_env_image_class_config(Context *c) {
        const char *env_var;
        int r;

        assert(c);

        env_var = secure_getenv(image_class_info[c->image_class].mode_env);
        if (env_var) {
                r = parse_mutable_mode(env_var);
                if (r < 0)
                        log_warning("Failed to parse %s environment variable value '%s'. Ignoring.",
                                    image_class_info[c->image_class].mode_env, env_var);
                else {
                        c->mutable = r;
                        c->mutable_set = true;
                }
        }

        env_var = secure_getenv(image_class_info[c->image_class].opts_env);
        if (env_var)
                c->overlayfs_mount_options = env_var;

        /* Debugging aid, to exercise the code path taken on kernels without support for mounting beneath */
        r = secure_getenv_bool(image_class_info[c->image_class].beneath_env);
        if (r >= 0)
                c->mount_beneath = r;
        else if (r != -ENXIO)
                log_warning_errno(r, "Failed to parse $%s, ignoring: %m", image_class_info[c->image_class].beneath_env);
}

static int parse_config_file(Context *c) {
        _cleanup_(image_policy_freep) ImagePolicy *config_image_policy = NULL;
        MutableMode config_mutable = MUTABLE_NO;
        const char *section, *sections;
        _cleanup_free_ char *config_file = NULL;
        int r;

        assert(c);

        section = c->image_class == IMAGE_SYSEXT ? "SysExt" : "ConfExt";
        sections = c->image_class == IMAGE_SYSEXT ? "SysExt\0" : "ConfExt\0";
        const ConfigTableItem items[] = {
                { section, "Mutable",           config_parse_mutable_mode,      0,      &config_mutable            },
                { section, "ImagePolicy",       config_parse_image_policy,      0,      &config_image_policy       },
                {}
        };

        config_file = strjoin("systemd/", image_class_info[c->image_class].short_identifier, ".conf");
        if (!config_file)
                return log_oom();

        r = config_parse_standard_file_with_dropins_full(
                        c->root,
                        /* root_fd= */ -EBADF,
                        config_file,
                        sections,
                        config_item_table_lookup, items,
                        CONFIG_PARSE_WARN,
                        /* userdata= */ NULL,
                        /* ret_stats_by_path= */ NULL,
                        /* ret_dropin_files= */ NULL);
        if (r < 0)
                return r;

        /* Configuration has the lowest priority, so only fill in values that neither the environment nor
         * argv initialized already. */
        if (!c->mutable_set) {
                c->mutable = config_mutable;
                c->mutable_set = true;
        }

        if (!c->image_policy_set) {
                c->image_policy = TAKE_PTR(config_image_policy);
                c->image_policy_set = true;
                c->image_policy_owned = true;
        }

        return 0;
}

static int context_from_cmdline(Context *ret, ImageClass image_class) {
        _cleanup_(context_done) Context c = CONTEXT_NULL;
        int r;

        assert(ret);

        /* Start with command-line settings shared by both image classes. Class-specific environment and
         * configuration are applied below, with argv values explicitly overriding both. */
        c.image_class = image_class;
        c.force = arg_force;
        c.no_reload = arg_no_reload;
        c.always_refresh = arg_always_refresh;
        c.noexec = arg_noexec;

        if (arg_root && strdup_to(&c.root, arg_root) < 0)
                return log_oom();

        r = parse_env_extension_hierarchies(&c.hierarchies, image_class_info[image_class].name_env);
        if (r < 0)
                return log_error_errno(r, "Failed to determine %s hierarchies: %m", image_class_info[image_class].short_identifier);

        /* Each hierarchy is processed once, also if listed repeatedly in the environment variable (possibly
         * with a trailing slash, which the normalization check allows) */
        STRV_FOREACH(h, c.hierarchies)
                path_simplify(*h);
        strv_uniq(c.hierarchies);

        parse_env_image_class_config(&c);

        if (arg_mutable_argv_set) {
                c.mutable = arg_mutable;
                c.mutable_set = true;
        }

        if (arg_image_policy_argv_set) {
                c.image_policy = arg_image_policy;
                c.image_policy_set = true;
                c.image_policy_owned = false;
        }

        r = parse_config_file(&c);
        if (r < 0)
                log_warning_errno(r, "Failed to parse %s config file, ignoring: %m", image_class_info[image_class].short_identifier);

        *ret = TAKE_GENERIC(c, Context, CONTEXT_NULL);
        return 0;
}

static int is_our_mount_point_fd(
                ImageClass image_class,
                int fd,
                const char *p) {

        _cleanup_free_ char *buf = NULL, *f = NULL;
        struct stat st;
        dev_t dev;
        int r;

        assert(fd >= 0);
        assert(p);

        r = is_mount_point_at(fd, /* path= */ NULL, /* flags= */ 0);
        if (r < 0)
                return log_error_errno(r, "Failed to determine whether '%s' is a mount point: %m", p);
        if (r == 0) {
                log_debug("Hierarchy '%s' is not a mount point, skipping.", p);
                return false;
        }

        /* So we know now that it's a mount point. Now let's check if it's one of ours, so that we don't
         * accidentally unmount the user's own /usr/ but just the mounts we established ourselves. We do this
         * check by looking into the metadata directory we place in merged mounts: if the file
         * ../dev contains the major/minor device pair of the mount we have a good reason to
         * believe this is one of our mounts. This thorough check has the benefit that we aren't easily
         * confused if people tar up one of our merged trees and untar them elsewhere where we might mistake
         * them for a live sysext tree. */

        f = path_join(image_class_info[image_class].dot_directory_name, "dev");
        if (!f)
                return log_oom();

        r = read_one_line_file_at(fd, f, &buf);
        if (r == -ENOENT) {
                log_debug("Hierarchy '%s' does not carry a %s/dev file, not a merged tree.", p, image_class_info[image_class].dot_directory_name);
                return false;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to determine whether hierarchy '%s' contains '%s/dev': %m", p, image_class_info[image_class].dot_directory_name);

        r = parse_devnum(buf, &dev);
        if (r < 0)
                return log_error_errno(r, "Failed to parse device major/minor stored in '%s/dev' file on '%s': %m", image_class_info[image_class].dot_directory_name, p);

        if (fstat(fd, &st) < 0)
                return log_error_errno(errno, "Failed to stat %s: %m", p);

        if (st.st_dev != dev) {
                log_debug("Hierarchy '%s' reports a different device major/minor than what we are seeing, assuming offline copy.", p);
                return false;
        }

        return true;
}

static int is_our_mount_point(
                ImageClass image_class,
                const char *p) {

        _cleanup_close_ int fd = -EBADF;

        assert(p);

        fd = xopenat(AT_FDCWD, p, O_PATH|O_DIRECTORY|O_NOFOLLOW);
        if (fd < 0) {
                if (IN_SET(fd, -ENOENT, -ENOTDIR)) {
                        log_debug_errno(fd, "Hierarchy '%s' doesn't exist or is not a directory.", p);
                        return false;
                }

                return log_error_errno(fd, "Failed to open '%s': %m", p);
        }

        return is_our_mount_point_fd(image_class, fd, p);
}

static int split_unit_string(const char *s, const char *field, const char *extension, Set **units) {
        _cleanup_strv_free_ char **split = NULL;
        int r;

        assert(field);
        assert(extension);
        assert(units);

        if (isempty(s))
                return 0;

        split = strv_split(s, /* separators= */ NULL);
        if (!split)
                return log_oom();

        STRV_FOREACH(u, split) {
                if (!unit_name_is_valid(*u, UNIT_NAME_PLAIN|UNIT_NAME_INSTANCE)) {
                        log_warning("Invalid unit name '%s' in %s= of %s, ignoring.", *u, field, extension);
                        continue;
                }

                r = set_put_strdup(units, *u);
                if (r < 0)
                        return log_oom();
        }

        return 0;
}

static int get_extension_release_metadata(
                const Context *c,
                bool *ret_need_reload,
                Set **ret_restart_units,
                Set **ret_reload_or_restart_units) {

        /* Parse the mounted images to find out if we need to reload the daemon, and which units to
         * restart or reload-or-restart afterwards. */
        _cleanup_set_free_ Set *restart_units = NULL, *reload_or_restart_units = NULL;
        bool need_to_reload = false;
        int r;

        assert(c);

        if (c->no_reload || !isempty(c->root)) {
                /* With --root= we'd be talking to the host service manager about extensions merged
                 * into a foreign root, which is never what we want. */
                if (ret_need_reload)
                        *ret_need_reload = false;
                if (ret_restart_units)
                        *ret_restart_units = NULL;
                if (ret_reload_or_restart_units)
                        *ret_reload_or_restart_units = NULL;
                return 0;
        }

        STRV_FOREACH(p, c->hierarchies) {
                _cleanup_free_ char *f = NULL, *buf = NULL, *resolved = NULL;
                _cleanup_strv_free_ char **mounted_extensions = NULL;

                r = chase(*p, c->root, CHASE_PREFIX_ROOT, &resolved, /* ret_fd= */ NULL);
                if (r == -ENOENT) {
                        log_debug_errno(r, "Hierarchy '%s%s' does not exist, ignoring.", strempty(c->root), *p);
                        continue;
                }
                if (r < 0) {
                        log_warning_errno(r, "Failed to resolve path to hierarchy '%s%s': %m, ignoring.", strempty(c->root), *p);
                        continue;
                }

                r = is_our_mount_point(c->image_class, resolved);
                if (r < 0)
                        return r;
                if (!r)
                        continue;

                f = path_join(resolved, image_class_info[c->image_class].dot_directory_name, image_class_info[c->image_class].short_identifier_plural);
                if (!f)
                        return log_oom();

                r = read_full_file(f, &buf, /* ret_size= */ NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to open '%s': %m", f);

                mounted_extensions = strv_split_newlines(buf);
                if (!mounted_extensions)
                        return log_oom();

                STRV_FOREACH(extension, mounted_extensions) {
                        _cleanup_strv_free_ char **extension_release = NULL;
                        const char *value;

                        r = load_extension_release_pairs(c->root, c->image_class, *extension, /* relax_extension_release_check= */ true, &extension_release);
                        if (r < 0) {
                                log_debug_errno(r, "Failed to parse extension-release metadata of %s, ignoring: %m", *extension);
                                continue;
                        }

                        value = strv_env_pairs_get(extension_release, "EXTENSION_RELOAD_MANAGER");
                        if (!isempty(value)) {
                                int b = parse_boolean(value);
                                if (b < 0)
                                        log_warning_errno(b, "Failed to parse EXTENSION_RELOAD_MANAGER= of %s, ignoring: %m", *extension);
                                else if (b)
                                        need_to_reload = true;
                        }

                        if (ret_restart_units) {
                                value = strv_env_pairs_get(extension_release, "EXTENSION_RESTART_UNITS");
                                r = split_unit_string(value, "EXTENSION_RESTART_UNITS", *extension, &restart_units);
                                if (r < 0)
                                        return r;
                                if (!isempty(value))
                                        /* Listing units to restart implies a manager reload because a unit
                                         * shipped (and later removed) by the extension would otherwise not
                                         * be visible to the manager when RestartUnit/StopUnit is issued. */
                                        need_to_reload = true;
                        }

                        if (ret_reload_or_restart_units) {
                                value = strv_env_pairs_get(extension_release, "EXTENSION_RELOAD_OR_RESTART_UNITS");
                                r = split_unit_string(value, "EXTENSION_RELOAD_OR_RESTART_UNITS", *extension, &reload_or_restart_units);
                                if (r < 0)
                                        return r;
                                if (!isempty(value))
                                        need_to_reload = true;
                        }
                }
        }

        /* If a unit is listed in both, restart takes precedence over reload-or-restart. */
        const char *u;
        SET_FOREACH(u, restart_units)
                free(set_remove(reload_or_restart_units, u));

        if (ret_need_reload)
                *ret_need_reload = need_to_reload;
        if (ret_restart_units)
                *ret_restart_units = TAKE_PTR(restart_units);
        if (ret_reload_or_restart_units)
                *ret_reload_or_restart_units = TAKE_PTR(reload_or_restart_units);
        return 0;
}

static int attach_submounts(
                SubMount *submounts,
                size_t n_submounts,
                const char *src,
                int dst_fd,
                const char *dst) {

        int r, ret = 0;

        assert(submounts || n_submounts == 0);
        assert(src);
        assert(dst_fd >= 0);
        assert(dst);

        /* Attaches the submount clones below dst_fd, which may refer to a detached mount ('dst' is only used
         * for logging). Continue on failure, so that as many submounts as possible end up in place. The
         * clones we cannot attach are lost once the caller frees them. */

        FOREACH_ARRAY(m, submounts, n_submounts) {
                _cleanup_free_ char *t = NULL;
                const char *suffix;
                struct stat st;

                assert_se(suffix = path_startswith(m->path, src));

                t = path_join(dst, suffix);
                if (!t)
                        return log_oom();

                if (fstat(m->mount_fd, &st) < 0) {
                        RET_GATHER(ret, log_error_errno(errno, "Failed to stat %s: %m", m->path));
                        continue;
                }

                _cleanup_free_ char *fn = NULL;
                _cleanup_close_ int fd = -EBADF;
                r = chaseat(dst_fd, dst_fd, suffix, CHASE_PARENT|CHASE_EXTRACT_FILENAME|CHASE_PROHIBIT_SYMLINKS|CHASE_MKDIR_0755, &fn, &fd);
                if (r < 0) {
                        RET_GATHER(ret, log_error_errno(r, "Failed to create and pin parent directory of %s: %m", t));
                        continue;
                }

                r = make_mount_point_inode_from_mode(fd, fn, st.st_mode, 0755);
                if (r < 0 && r != -EEXIST) {
                        RET_GATHER(ret, log_error_errno(r, "Failed to create mountpoint %s: %m", t));
                        continue;
                }

                _cleanup_close_ int child_fd = xopenat(fd, fn, O_PATH);
                if (child_fd < 0) {
                        RET_GATHER(ret, log_error_errno(child_fd, "Failed to pin mountpoint %s: %m", t));
                        continue;
                }

                /* Instead of a bind mount we attach the detached clone produced by
                 * open_tree_attr_with_fallback() from get_sub_mounts() because that has no propagation
                 * relationship with the original anymore. */
                r = RET_NERRNO(move_mount(m->mount_fd, "", child_fd, "", MOVE_MOUNT_F_EMPTY_PATH|MOVE_MOUNT_T_EMPTY_PATH));
                if (r < 0)
                        RET_GATHER(ret, log_error_errno(r, "Failed to move mount '%s' to '%s': %m", m->path, t));
        }

        return ret;
}

static int daemon_reload(void) {
         _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        r = bus_connect_system_systemd(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to get D-Bus connection: %m");

        return bus_service_manager_reload(bus);
}

static int dispatch_unit_method(sd_bus *bus, BusWaitForJobs *w, Set *units, const char *method) {
        const char *unit;
        int r;

        assert(bus);
        assert(w);
        assert(method);

        /* Issue the given method for each unit and wait for the jobs to complete. Fall back to StopUnit
         * when the call reports that the unit's file is gone, e.g., on unmerge when the unit was part of
         * the extension, because otherwise the running service is leaked. */

        SET_FOREACH(unit, units) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                const char *m = method, *job;

                r = bus_call_method(bus, bus_systemd_mgr, m, &error, &reply, "ss", unit, "replace");
                if (r < 0 && sd_bus_error_has_names(&error, BUS_ERROR_NO_SUCH_UNIT, BUS_ERROR_LOAD_FAILED)) {
                        sd_bus_error_free(&error);
                        m = "StopUnit";
                        r = bus_call_method(bus, bus_systemd_mgr, m, &error, &reply, "ss", unit, "replace");
                        if (r < 0 && sd_bus_error_has_name(&error, BUS_ERROR_NO_SUCH_UNIT)) {
                                log_debug("Unit '%s' is already gone, nothing to stop.", unit);
                                continue;
                        }
                }
                if (r < 0) {
                        log_warning("Failed to %s unit '%s': %s", m, unit, bus_error_message(&error, r));
                        continue;
                }

                r = sd_bus_message_read(reply, "o", &job);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = bus_wait_for_jobs_one(w, job, BUS_WAIT_JOBS_LOG_ERROR);
                if (r < 0)
                        log_warning_errno(r, "Failed to wait for %s job of unit '%s', ignoring: %m", m, unit);
        }

        return 0;
}

static int restart_units(Set *restart_units, Set *reload_or_restart_units) {
         _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
         _cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *w = NULL;
        int r;

        if (set_isempty(restart_units) && set_isempty(reload_or_restart_units))
                return 0;

        r = bus_connect_system_systemd(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to get D-Bus connection: %m");

        r = bus_wait_for_jobs_new(bus, &w);
        if (r < 0)
                return log_error_errno(r, "Failed to set up job watcher: %m");

        r = dispatch_unit_method(bus, w, restart_units, "RestartUnit");
        if (r < 0)
                return r;

        r = dispatch_unit_method(bus, w, reload_or_restart_units, "ReloadOrRestartUnit");
        if (r < 0)
                return r;

        return 0;
}

static char *hierarchy_as_single_path_component(const char *hierarchy) {
        /* We normally expect hierarchy to be /usr, /opt or /etc, but for debugging purposes the hierarchy
         * could very well be like /foo/bar/baz/. So for a given hierarchy we generate a directory name by
         * stripping the leading and trailing separators and replacing the rest of separators with dots. This
         * makes the generated name to be the same for /foo/bar/baz and for /foo/bar.baz, but, again,
         * specifying a different hierarchy is a debugging feature, so non-unique mapping should not be an
         * issue in general case. */
        const char *stripped = hierarchy;
        _cleanup_free_ char *dir_name = NULL;

        assert(hierarchy);

        stripped += strspn(stripped, "/");

        dir_name = strdup(stripped);
        if (!dir_name)
                return NULL;
        delete_trailing_chars(dir_name, "/");
        string_replace_char(dir_name, '/', '.');
        return TAKE_PTR(dir_name);
}

static int paths_on_same_fs(const char *path1, const char *path2) {
        struct stat st1, st2;

        assert(path1);
        assert(path2);

        if (stat(path1, &st1) < 0)
                return log_error_errno(errno, "Failed to stat '%s': %m", path1);

        if (stat(path2, &st2) < 0)
                return log_error_errno(errno, "Failed to stat '%s': %m", path2);

        return st1.st_dev == st2.st_dev;
}

static int work_dir_name_for_hierarchy(const char *hierarchy, char **ret) {
        _cleanup_free_ char *f = NULL;

        assert(hierarchy);
        assert(ret);

        f = hierarchy_as_single_path_component(hierarchy);
        if (!f)
                return log_oom();

        /* Use a unique name per merge, so that a refresh never reuses the work dir of the overlayfs
         * instance that is still mounted while the new one is set up. */
        if (asprintf(ret, ".systemd-%s-workdir-%016" PRIx64, f, random_u64()) < 0)
                return log_oom();

        return 0;
}

static int parse_image_class_parameter(sd_varlink *link, const char *value, ImageClass *image_class) {
        ImageClass c;

        assert(link);
        assert(image_class);

        if (!value)
                return 0;

        c = image_class_from_string(value);
        if (!IN_SET(c, IMAGE_SYSEXT, IMAGE_CONFEXT))
                return sd_varlink_error_invalid_parameter_name(link, "class");

        *image_class = c;
        return 0;
}

static int resolve_hierarchy(const Context *c, const char *hierarchy, char **ret_resolved_hierarchy) {
        _cleanup_free_ char *resolved_path = NULL;
        int r;

        assert(c);
        assert(hierarchy);
        assert(ret_resolved_hierarchy);

        r = chase(hierarchy, c->root, CHASE_PREFIX_ROOT, &resolved_path, /* ret_fd= */ NULL);
        if (r < 0 && r != -ENOENT)
                return log_error_errno(r, "Failed to resolve hierarchy '%s': %m", hierarchy);

        *ret_resolved_hierarchy = TAKE_PTR(resolved_path);
        return 0;
}

static int mutable_directory_mode_matches_hierarchy(
                const char *root_or_null,
                const char *path,
                mode_t hierarchy_mode) {

        _cleanup_free_ char *path_in_root = NULL;
        struct stat st;
        mode_t actual_mode;

        assert(path);

        path_in_root = path_join(root_or_null, path);
        if (!path_in_root)
                return log_oom();

        if (stat(path_in_root, &st) < 0) {
                if (errno == ENOENT)
                        return 0;
                return log_error_errno(errno, "Failed to stat mutable directory '%s': %m", path_in_root);
        }

        actual_mode = st.st_mode & 0777;
        if (actual_mode != hierarchy_mode)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Mutable directory '%s' has mode %04o, ought to have mode %04o", path_in_root, actual_mode, hierarchy_mode);

        return 0;
}

static int resolve_mutable_directory(
                const Context *c,
                const char *hierarchy,
                mode_t hierarchy_mode,
                char **ret_resolved_mutable_directory) {

        _cleanup_free_ char *path = NULL, *resolved_path = NULL, *dir_name = NULL;
        int r;

        assert(c);
        assert(hierarchy);
        assert(ret_resolved_mutable_directory);

        /* The ephemeral modes have no persistent mutable directory, they get a new tmpfs on each merge. */
        if (IN_SET(c->mutable, MUTABLE_NO, MUTABLE_EPHEMERAL, MUTABLE_EPHEMERAL_IMPORT)) {
                log_debug("Hierarchy '%s' has no persistent mutable directory.", hierarchy);
                *ret_resolved_mutable_directory = NULL;
                return 0;
        }

        dir_name = hierarchy_as_single_path_component(hierarchy);
        if (!dir_name)
                return log_oom();

        path = path_join(MUTABLE_EXTENSIONS_BASE_DIR, dir_name);
        if (!path)
                return log_oom();

        if (IN_SET(c->mutable, MUTABLE_YES, MUTABLE_AUTO)) {
                /* If there already is a mutable directory, check if its mode matches hierarchy. Merged
                 * hierarchy will have the same mode as the mutable directory, so we want no surprising mode
                 * changes here. */
                r = mutable_directory_mode_matches_hierarchy(c->root, path, hierarchy_mode);
                if (r < 0)
                        return r;
        }

        if (c->mutable == MUTABLE_YES) {
                _cleanup_close_ int path_fd = -EBADF, chmod_fd = -EBADF;

                /* This also creates, e.g., /var/lib/extensions.mutable/usr if needed and all parent
                 * directories plus it also works when the last part is a symlink to the real /usr but we
                 * can't use chase_and_open here because it does not behave the same. */
                r = chase(path, c->root, CHASE_MKDIR_0755|CHASE_MUST_BE_DIRECTORY|CHASE_PREFIX_ROOT, /* ret_path= */ NULL, &path_fd);
                if (r < 0)
                        return log_error_errno(r, "Failed to chase/create base directory '%s/%s': %m", strempty(c->root), skip_leading_slash(path));

                chmod_fd = fd_reopen(path_fd, O_DIRECTORY);
                if (chmod_fd < 0)
                        return log_error_errno(chmod_fd, "Failed to reopen '%s/%s': %m", strempty(c->root), skip_leading_slash(path));

                if (fchmod(chmod_fd, hierarchy_mode) < 0)
                        return log_error_errno(errno, "Failed to chmod directory '%s/%s': %m", strempty(c->root), skip_leading_slash(path));

                r = mac_selinux_fix_full(chmod_fd, /* inode_path= */ NULL, hierarchy, /* flags= */ 0, /* label_context= */ NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to fix SELinux label for '%s/%s': %m", strempty(c->root), skip_leading_slash(path));
        }

        r = chase(path, c->root, CHASE_PREFIX_ROOT, &resolved_path, /* ret_fd= */ NULL);
        if (r < 0 && r != -ENOENT)
                return log_error_errno(r, "Failed to resolve mutable directory '%s': %m", path);

        *ret_resolved_mutable_directory = TAKE_PTR(resolved_path);
        return 0;
}

static int hierarchy_mutable_directory(const Context *c, const char *hierarchy, char **ret) {
        _cleanup_free_ char *resolved_hierarchy = NULL;
        mode_t hierarchy_mode = 0755;
        int r;

        assert(c);
        assert(hierarchy);
        assert(ret);

        r = resolve_hierarchy(c, hierarchy, &resolved_hierarchy);
        if (r < 0)
                return r;

        if (resolved_hierarchy) {
                struct stat st;

                if (stat(resolved_hierarchy, &st) < 0)
                        return log_error_errno(errno, "Failed to stat '%s': %m", resolved_hierarchy);
                hierarchy_mode = st.st_mode & 0777;
        }

        return resolve_mutable_directory(c, hierarchy, hierarchy_mode, ret);
}

static int make_ephemeral_mutable_directory(
                const Context *c,
                const char *hierarchy,
                mode_t hierarchy_mode,
                int *ret_tmpfs_fd,
                char **ret_dir_name) {

        _cleanup_free_ char *dir_name = NULL;
        _cleanup_close_ int tmpfs_fd = -EBADF, fd = -EBADF;
        int r;

        assert(c);
        assert(hierarchy);
        assert(ret_tmpfs_fd);
        assert(ret_dir_name);

        /* Creates a detached tmpfs with the mutable directory of the ephemeral modes in it, the work
         * directory goes next to it. */

        dir_name = hierarchy_as_single_path_component(hierarchy);
        if (!dir_name)
                return log_oom();

        tmpfs_fd = make_fsmount(LOG_ERR, image_class_info[c->image_class].short_identifier, "tmpfs", /* flags= */ 0, "mode=0700", /* userns_fd= */ -EBADF);
        if (tmpfs_fd < 0)
                return tmpfs_fd;

        fd = open_mkdir_at(tmpfs_fd, dir_name, O_NOFOLLOW, 0755);
        if (fd < 0)
                return log_error_errno(fd, "Failed to create ephemeral mutable directory for '%s': %m", hierarchy);

        if (fchmod(fd, hierarchy_mode) < 0)
                return log_error_errno(errno, "Failed to chmod ephemeral mutable directory for '%s': %m", hierarchy);

        r = mac_selinux_fix_full(fd, /* inode_path= */ NULL, hierarchy, /* flags= */ 0, /* label_context= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to fix SELinux label of ephemeral mutable directory for '%s': %m", hierarchy);

        *ret_tmpfs_fd = TAKE_FD(tmpfs_fd);
        *ret_dir_name = TAKE_PTR(dir_name);
        return 0;
}

static int write_meta_file(
                ImageClass image_class,
                int meta_fd,
                const char *name,
                const char *content,
                WriteStringFileFlags flags,
                const char *hierarchy,
                const char *label_name) {

        _cleanup_free_ char *f = NULL, *label_path = NULL;
        int r;

        assert(meta_fd >= 0);
        assert(name);
        assert(hierarchy);
        assert(label_name);

        f = path_join(image_class_info[image_class].dot_directory_name, name);
        if (!f)
                return log_oom();

        label_path = path_join(hierarchy, image_class_info[image_class].dot_directory_name, label_name);
        if (!label_path)
                return log_oom();

        r = write_string_file_full(meta_fd, f, strempty(content), WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_LABEL|flags, /* ts= */ NULL, label_path);
        if (r < 0)
                return log_error_errno(r, "Failed to write metadata file '%s': %m", f);

        return 0;
}

static int store_info_in_meta(
                const Context *c,
                int meta_fd,
                char **extensions,
                const char *origin_content,
                const char *work_dir,
                const char *hierarchy,
                dev_t backing) {

        const char *plural = image_class_info[c->image_class].short_identifier_plural;
        _cleanup_close_ int dot_fd = -EBADF;
        int r;

        assert(c);
        assert(meta_fd >= 0);
        assert(hierarchy);
        /* work_dir may be NULL */

        /* The metadata is written before the overlayfs is created, except for the device number of the
         * overlayfs itself, see write_dev_file(). */

        dot_fd = open_mkdir_at(meta_fd, image_class_info[c->image_class].dot_directory_name, O_NOFOLLOW, 0755);
        if (dot_fd < 0)
                return log_error_errno(dot_fd, "Failed to create metadata directory for '%s': %m", hierarchy);

        r = mac_selinux_fix_full(dot_fd, /* inode_path= */ NULL, hierarchy, /* flags= */ 0, /* label_context= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to fix SELinux label for '%s': %m", hierarchy);

        /* Let's generate a metadata file that lists all extensions we took into account for this
         * hierarchy. We include this in the final fs, to make things nicely discoverable and
         * recognizable. */
        _cleanup_free_ char *buf = NULL;
        if (!strv_isempty(extensions)) {
                buf = strv_join(extensions, "\n");
                if (!buf)
                        return log_oom();

                if (!strextend(&buf, "\n")) /* manually append newline since we want to suppress newline if zero extensions are applied */
                        return log_oom();
        }

        r = write_meta_file(c->image_class, meta_fd, plural, buf, WRITE_STRING_FILE_AVOID_NEWLINE, hierarchy, plural);
        if (r < 0)
                return r;

        /* The origin file is compared to know if a refresh can be skipped (opt-in, used at service startup). */
        r = write_meta_file(c->image_class, meta_fd, "origin", origin_content, WRITE_STRING_FILE_AVOID_NEWLINE, hierarchy, plural);
        if (r < 0)
                return r;

        /* Do not store work dir path for ephemeral mode, it will be gone once this process is done. */
        if (work_dir && !IN_SET(c->mutable, MUTABLE_EPHEMERAL, MUTABLE_EPHEMERAL_IMPORT)) {
                _cleanup_free_ char *escaped_work_dir_in_root = NULL;
                const char *work_dir_in_root;

                work_dir_in_root = path_startswith(work_dir, empty_to_root(c->root));
                if (!work_dir_in_root)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Workdir '%s' must not be outside root '%s'", work_dir, empty_to_root(c->root));

                /* Paths can have newlines for whatever reason, so better escape them to really get a single
                 * line file. */
                escaped_work_dir_in_root = cescape(work_dir_in_root);
                if (!escaped_work_dir_in_root)
                        return log_oom();

                r = write_meta_file(c->image_class, meta_fd, "work_dir", escaped_work_dir_in_root, /* flags= */ 0, hierarchy, "work_dir");
                if (r < 0)
                        return r;
        }

        /* Let's also store away the backing file system dev_t, so that applications can trace back what
         * they are looking at here */
        if (backing != 0) {
                r = write_meta_file(c->image_class, meta_fd, "backing", FORMAT_DEVNUM(backing), /* flags= */ 0, hierarchy, plural);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int write_dev_file(const Context *c, int meta_fd, int overlay_fd, const char *hierarchy) {
        struct stat st;
        int r;

        assert(c);
        assert(meta_fd >= 0);
        assert(overlay_fd >= 0);
        assert(hierarchy);

        /* Now we have created the new file system. Let's now figure out its .st_dev field, and make that
         * available in the metadata directory. This is useful to detect whether the metadata dir actually
         * belongs to the fs it is found on: if .st_dev of the top-level mount matches it, it's pretty likely
         * we are looking at a live tree, and not an unpacked tar or so of one. */
        if (fstat(overlay_fd, &st) < 0)
                return log_error_errno(errno, "Failed to stat overlayfs for '%s': %m", hierarchy);

        /* Modifying the underlying layers while the overlayfs is mounted is technically undefined, but at
         * least it won't crash or deadlock, as per the kernel docs about overlayfs:
         * https://www.kernel.org/doc/html/latest/filesystems/overlayfs.html#changes-to-underlying-filesystems */
        r = write_meta_file(c->image_class, meta_fd, "dev", FORMAT_DEVNUM(st.st_dev), /* flags= */ 0, hierarchy, image_class_info[c->image_class].short_identifier_plural);
        if (r < 0)
                return r;

        /* Make sure the top-level dir has an mtime marking the point we established the merge */
        r = futimens_opath(meta_fd, /* ts= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to fix mtime of metadata of '%s': %m", hierarchy);

        return 0;
}

static int make_meta_read_only(const Context *c, int overlay_fd, const char *hierarchy, unsigned long flags, const char *options) {
        const char *dot_dir = image_class_info[c->image_class].dot_directory_name;
        _cleanup_close_ int fd = -EBADF;
        bool remount;
        int r;

        assert(c);
        assert(overlay_fd >= 0);
        assert(hierarchy);

        /* Bind mount the meta directory as read-only on mutable overlays to avoid accidental modifications
         * of the contents of meta directory, which could lead to systemd thinking that this hierarchy is
         * not our mount. 'overlay_fd' may refer to a detached mount. */

        fd = open_tree_attr_with_fallback(overlay_fd, dot_dir, OPEN_TREE_CLONE|AT_SYMLINK_NOFOLLOW,
                                          &(struct mount_attr) { .attr_set = MOUNT_ATTR_RDONLY });
        remount = ERRNO_IS_NEG_NOT_SUPPORTED(fd);
        if (remount) {
                // FIXME: This compatibility code path shall be removed once kernel 5.12
                //        becomes the new minimal baseline
                /* Without mount_setattr() remount once attached instead */
                fd = RET_NERRNO(open_tree(overlay_fd, dot_dir, OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC|AT_SYMLINK_NOFOLLOW));
        }
        if (fd < 0)
                return log_error_errno(fd, "Failed to clone metadata directory of '%s': %m", hierarchy);

        r = RET_NERRNO(move_mount(fd, "", overlay_fd, dot_dir, MOVE_MOUNT_F_EMPTY_PATH));
        if (r < 0)
                return log_error_errno(r, "Failed to mount metadata directory of '%s' read-only: %m", hierarchy);

        if (remount) {
                unsigned long f;

                r = mount_option_mangle(options, flags, &f, /* ret_remaining_options= */ NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse mount options of '%s': %m", hierarchy);

                f &= MS_NOSUID|MS_NODEV|MS_NOEXEC|MS_NOATIME|MS_NODIRATIME|MS_RELATIME|MS_STRICTATIME;
                r = mount_follow_verbose(LOG_ERR, /* what= */ NULL, FORMAT_PROC_FD_PATH(fd), /* fstype= */ NULL, MS_BIND|MS_REMOUNT|MS_RDONLY|f, /* options= */ NULL);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int strverscmp_improvedp(char *const* a, char *const* b) {
        assert(a);
        assert(b);

        /* usable in qsort() for sorting a string array with strverscmp_improved() */
        return strverscmp_improved(*a, *b);
}

static const ImagePolicy* pick_image_policy(const Context *c, const Image *img) {
        assert(c);
        assert(img);
        assert(img->path);

        /* Explicitly specified policy always wins */
        if (c->image_policy)
                return c->image_policy;

        /* If located in /.extra/ in the initrd, then it was placed there by systemd-stub, and was
         * picked up from an untrusted ESP. Thus, require a stricter policy by default for them. (For the
         * other directories we assume the appropriate level of trust was already established.)
         * With --root= we default to the regular policy, though. (To change that, the check would need
         * to prepend (or cut away) c->root.) */

        if (in_initrd() && !c->root) {
                if (path_startswith(img->path, "/.extra/sysext/"))
                        return &image_policy_sysext_strict;
                if (path_startswith(img->path, "/.extra/global_sysext/"))
                        return &image_policy_sysext_strict;
                if (path_startswith(img->path, "/.extra/confext/"))
                        return &image_policy_confext_strict;
                if (path_startswith(img->path, "/.extra/global_confext/"))
                        return &image_policy_confext_strict;

                /* Better safe than sorry, refuse everything else passed in via the untrusted /.extra/ dir */
                if (path_startswith(img->path, "/.extra/"))
                        return &image_policy_deny;
        }

        return image_class_info[img->class].default_image_policy;
}

static int read_work_dir_at(
                const Context *c,
                int dir_fd,
                const char *hierarchy_path,
                const char *log_path,
                char **ret) {

        _cleanup_free_ char *work_dir_info_file = NULL, *escaped_work_dir_in_root = NULL,
                        *work_dir_in_root = NULL, *work_dir = NULL;
        ssize_t l;
        int r;

        assert(c);
        assert(hierarchy_path);
        assert(log_path);
        assert(ret);

        work_dir_info_file = path_join(hierarchy_path, image_class_info[c->image_class].dot_directory_name, "work_dir");
        if (!work_dir_info_file)
                return log_oom();

        r = read_one_line_file_at(dir_fd, work_dir_info_file, &escaped_work_dir_in_root);
        if (r == -ENOENT) {
                *ret = NULL;
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to read work directory path of hierarchy '%s': %m", log_path);

        l = cunescape(escaped_work_dir_in_root, /* flags= */ 0, &work_dir_in_root);
        if (l < 0)
                return log_error_errno(l, "Failed to unescape work directory path of hierarchy '%s': %m", log_path);
        if (path_is_absolute(work_dir_in_root) || !path_is_normalized(work_dir_in_root))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Invalid work directory path '%s' of hierarchy '%s'.", work_dir_in_root, log_path);

        work_dir = path_join(empty_to_root(c->root), work_dir_in_root);
        if (!work_dir)
                return log_oom();

        *ret = TAKE_PTR(work_dir);
        return 1;
}

static int unmerge_hierarchy(
                const Context *c,
                const char *p,
                SubMount **ret_submounts,
                size_t *ret_n_submounts) {

        _cleanup_free_ char *dot_dir = NULL;
        SubMount *submounts = NULL;
        size_t n_submounts = 0;
        int n_unmerged = 0;
        int r;

        assert(c);
        assert(p);
        assert(ret_submounts);
        assert(ret_n_submounts);

        CLEANUP_ARRAY(submounts, n_submounts, sub_mount_array_free);

        /* Detached clones of the submounts below the hierarchy are returned for the caller to attach them
         * where they belong now. */

        dot_dir = path_join(p, image_class_info[c->image_class].dot_directory_name);
        if (!dot_dir)
                return log_oom();

        for (;;) {
                _cleanup_free_ char *work_dir = NULL;
                SubMount *layer_submounts = NULL;
                size_t n_layer_submounts = 0;

                CLEANUP_ARRAY(layer_submounts, n_layer_submounts, sub_mount_array_free);

                /* We only unmount /usr/ if it is a mount point and really one of ours, in order not to break
                 * systems where /usr/ is a mount point of its own already. */

                r = is_our_mount_point(c->image_class, p);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                r = read_work_dir_at(c, AT_FDCWD, p, p, &work_dir);
                if (r < 0)
                        return r;

                r = umount_verbose(LOG_DEBUG, dot_dir, MNT_DETACH|UMOUNT_NOFOLLOW);
                if (r < 0) {
                        /* EINVAL is possibly "not a mount point". Let it slide as it's expected to occur if
                         * the whole hierarchy was read-only, so the dot directory inside it was not
                         * bind-mounted as read-only. */
                        if (r != -EINVAL)
                                return log_error_errno(r, "Failed to unmount '%s': %m", dot_dir);
                }

                /* After we've unmounted the metadata directory, save all other submounts so that they can
                 * be restored after unmerging the hierarchy. */
                r = get_sub_mounts(p, &layer_submounts, &n_layer_submounts);
                if (r < 0)
                        return log_error_errno(r, "Failed to get submounts for %s: %m", p);

                if (!GREEDY_REALLOC(submounts, n_submounts + n_layer_submounts))
                        return log_oom();
                FOREACH_ARRAY(m, layer_submounts, n_layer_submounts)
                        submounts[n_submounts++] = (SubMount) {
                                .path = TAKE_PTR(m->path),
                                .mount_fd = TAKE_FD(m->mount_fd),
                                .original_fd = TAKE_FD(m->original_fd),
                        };

                r = umount_verbose(LOG_ERR, p, MNT_DETACH|UMOUNT_NOFOLLOW);
                if (r < 0)
                        return r;

                /* Note that on the error paths from here on (and in further iterations for stacked
                 * overlayfs mounts) the clones collected so far are destroyed without being returned, while
                 * the originals are gone with the unmounted overlayfs already, hence the submounts are lost
                 * for the caller. We could hand out what we have on error, too, so that the caller can put
                 * it back in place, but that is probably not worth the complexity. */

                if (work_dir) {
                        r = rm_rf(work_dir, REMOVE_ROOT | REMOVE_MISSING_OK | REMOVE_PHYSICAL);
                        if (r < 0)
                                return log_error_errno(r, "Failed to remove '%s', submounts of '%s' might be lost: %m", work_dir, p);
                }

                log_info("Unmerged '%s'.", p);
                n_unmerged++;
        }

        *ret_submounts = TAKE_PTR(submounts);
        *ret_n_submounts = n_submounts;
        n_submounts = 0;

        return n_unmerged;
}

static int unmerge_hierarchy_in_place(const Context *c, const char *p) {
        SubMount *submounts = NULL;
        size_t n_submounts = 0;
        int r, n_unmerged;

        assert(c);
        assert(p);

        CLEANUP_ARRAY(submounts, n_submounts, sub_mount_array_free);

        /* Unmerges the hierarchy and puts its submounts back in place on the bare hierarchy. */

        n_unmerged = unmerge_hierarchy(c, p, &submounts, &n_submounts);
        if (n_unmerged <= 0)
                return n_unmerged;

        _cleanup_close_ int fd = xopenat(AT_FDCWD, p, O_PATH|O_DIRECTORY|O_NOFOLLOW);
        if (fd < 0)
                return log_error_errno(fd, "Failed to open '%s': %m", p);

        r = attach_submounts(submounts, n_submounts, p, fd, p);
        if (r < 0)
                return r;

        return n_unmerged;
}

static int unmerge_hierarchies(const Context *c) {
        int r, ret = 0;

        assert(c);

        STRV_FOREACH(h, c->hierarchies) {
                _cleanup_free_ char *resolved = NULL;

                r = chase(*h, c->root, CHASE_PREFIX_ROOT, &resolved, /* ret_fd= */ NULL);
                if (r == -ENOENT) {
                        log_debug_errno(r, "Hierarchy '%s%s' does not exist, ignoring.", strempty(c->root), *h);
                        continue;
                }
                if (r < 0) {
                        RET_GATHER(ret, log_error_errno(r, "Failed to resolve path to hierarchy '%s%s': %m", strempty(c->root), *h));
                        continue;
                }

                RET_GATHER(ret, unmerge_hierarchy_in_place(c, resolved));
        }

        return ret;
}

static int unmerge(const Context *c) {

        _cleanup_set_free_ Set *units_to_restart = NULL, *units_to_reload_or_restart = NULL;
        bool need_to_reload;
        int r;

        assert(c);

        (void) dlopen_libmount(LOG_DEBUG);

        r = get_extension_release_metadata(c, &need_to_reload, &units_to_restart, &units_to_reload_or_restart);
        if (r < 0)
                return r;

        r = unmerge_hierarchies(c);
        if (r < 0)
                return r;

        if (need_to_reload) {
                r = daemon_reload();
                if (r < 0)
                        return r;
        }

        /* The sets will be empty when opted out */
        r = restart_units(units_to_restart, units_to_reload_or_restart);
        if (r < 0)
                return r;

        return 0;
}

static int unpeel_hierarchy(const Context *c, const char *p, int *ret_fd) {
        _cleanup_close_pair_ int pair[2] = EBADF_PAIR;
        int r;

        assert(c);
        assert(p);
        assert(ret_fd);

        /* Returns a detached clone of what is beneath our overlayfs mounts on the hierarchy. There is no
         * way to get at a mount that is covered at its root other than unmounting what covers it, hence do
         * that in a private mount namespace of a child, while the host keeps the old overlayfs. */

        if (socketpair(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC, 0, pair) < 0)
                return log_error_errno(errno, "Failed to create socket pair: %m");

        r = pidref_safe_fork("(sd-unpeel)", FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_WAIT|FORK_NEW_MOUNTNS|FORK_MOUNTNS_SLAVE, /* ret= */ NULL);
        if (r < 0)
                return r;
        if (r == 0) {
                _cleanup_close_ int fd = -EBADF;

                pair[0] = safe_close(pair[0]);

                for (;;) {
                        r = is_our_mount_point(c->image_class, p);
                        if (r < 0)
                                _exit(EXIT_FAILURE);
                        if (r == 0)
                                break;

                        r = umount_verbose(LOG_ERR, p, MNT_DETACH|UMOUNT_NOFOLLOW);
                        if (r < 0)
                                _exit(EXIT_FAILURE);
                }

                fd = open_tree(AT_FDCWD, p, OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC|AT_SYMLINK_NOFOLLOW);
                if (fd < 0) {
                        log_error_errno(errno, "Failed to clone '%s': %m", p);
                        _exit(EXIT_FAILURE);
                }

                r = send_one_fd(pair[1], fd, /* flags= */ 0);
                if (r < 0) {
                        log_error_errno(r, "Failed to send mount of '%s': %m", p);
                        _exit(EXIT_FAILURE);
                }

                _exit(EXIT_SUCCESS);
        }

        pair[1] = safe_close(pair[1]);

        r = receive_one_fd(pair[0], MSG_DONTWAIT);
        if (r < 0)
                return log_error_errno(r, "Failed to receive mount of '%s': %m", p);

        *ret_fd = r;
        return 0;
}

typedef struct ExtensionMount {
        char *name;
        int root_fd;    /* the root partition, or the directory of the extension */
        int usr_fd;     /* a separate /usr partition */
} ExtensionMount;

#define EXTENSION_MOUNT_NULL                    \
        (ExtensionMount) {                      \
                .root_fd = -EBADF,              \
                .usr_fd = -EBADF,               \
        }

static void extension_mount_done(ExtensionMount *m) {
        assert(m);

        m->name = mfree(m->name);
        m->root_fd = safe_close(m->root_fd);
        m->usr_fd = safe_close(m->usr_fd);
}

static DEFINE_ARRAY_FREE_FUNC(extension_mount_array_free, ExtensionMount, extension_mount_done);

static ExtensionMount* extension_mount_find(ExtensionMount *mounts, size_t n_mounts, const char *name) {
        assert(mounts || n_mounts == 0);
        assert(name);

        FOREACH_ARRAY(m, mounts, n_mounts)
                if (streq(m->name, name))
                        return m;

        return NULL;
}

static int extension_mount_dir(const ExtensionMount *m, const char *path, int *ret_fd, const char **ret_fd_path) {
        assert(m);
        assert(path);
        assert(ret_fd);
        assert(ret_fd_path);

        /* Returns the fd that 'path' of the extension's tree is found below, and the path the fd corresponds
         * to in the tree. The partitions of an image are separate detached mounts, so /usr may live on a
         * mount of its own. */

        if (m->usr_fd >= 0 && path_startswith(path, "/usr")) {
                *ret_fd = m->usr_fd;
                *ret_fd_path = "/usr";
                return 0;
        }

        if (m->root_fd >= 0) {
                *ret_fd = m->root_fd;
                *ret_fd_path = "/";
                return 0;
        }

        return -ENOENT;
}

static int extension_mount_is_valid(const ExtensionMount *m) {
        static const ImageClass classes[] = { IMAGE_SYSEXT, IMAGE_CONFEXT };
        const char *fd_path;
        int fd, r;

        assert(m);

        /* Checks what DISSECT_IMAGE_VALIDATE_OS_EXT checks for images mounted to a path: that the image
         * doesn't carry /usr/lib/os-release, and that it is an extension of either class. Returns > 0 if
         * the image is good. */

        if (extension_mount_dir(m, "/usr/lib/os-release", &fd, &fd_path) >= 0) {
                r = extension_has_forbidden_content_at(fd, fd_path);
                if (r < 0)
                        return log_error_errno(r, "Failed to check image '%s' for forbidden content: %m", m->name);
                if (r > 0)
                        return false;
        }

        FOREACH_ELEMENT(class, classes) {
                if (extension_mount_dir(m, *class == IMAGE_SYSEXT ? "/usr/lib/extension-release.d" : "/etc/extension-release.d", &fd, &fd_path) < 0)
                        continue;

                r = open_extension_release_at_full(fd, fd_path, *class, m->name, /* relax_extension_release_check= */ false, /* ret_path= */ NULL, /* ret_fd= */ NULL);
                if (r >= 0)
                        return true;
                if (r != -ENOENT)
                        return log_error_errno(r, "Failed to look for extension-release file of '%s': %m", m->name);
        }

        log_debug("Image '%s' is not an extension.", m->name);
        return false;
}

typedef struct HierarchyMerge {
        const char *hierarchy;          /* as configured */
        char *resolved;                 /* the hierarchy below the root */
        char *name;
        int parent_fd;
        int hierarchy_fd;               /* -EBADF if the hierarchy doesn't exist (yet) */
        bool replacing;                 /* our previous overlayfs is mounted there */
        char *old_work_dir;             /* the work dir of the previous overlayfs */
        SubMount *submounts;            /* clones of what is mounted below the hierarchy */
        size_t n_submounts;
        int base_fd;                    /* the hierarchy itself, as layer of the new overlayfs */
        int meta_fd;                    /* tmpfs with the metadata of this merge */
        int import_fd;                  /* imported mutable directory */
        int upper_dir_fd;               /* contains upper and work dir, -EBADF if read-only */
        char *upper;
        char *work;
        char *work_dir;                 /* path of the work dir we created, if not ephemeral */
        OverlayFSLayer *layers;
        size_t n_layers;
        char **layer_paths;             /* owns the paths in 'layers' */
        unsigned long flags;
        char *options;
        int overlay_fd;
        bool mounted;
} HierarchyMerge;

#define HIERARCHY_MERGE_NULL                    \
        (HierarchyMerge) {                      \
                .parent_fd = -EBADF,            \
                .hierarchy_fd = -EBADF,         \
                .base_fd = -EBADF,              \
                .meta_fd = -EBADF,              \
                .import_fd = -EBADF,            \
                .upper_dir_fd = -EBADF,         \
                .overlay_fd = -EBADF,           \
        }

static void hierarchy_merge_done(HierarchyMerge *hm) {
        assert(hm);

        /* Unless the overlayfs got mounted, nothing but itself uses the work directory we created. Close it
         * first, so that the directory is unused when we remove it. */
        hm->overlay_fd = safe_close(hm->overlay_fd);
        if (!hm->mounted && hm->work_dir && hm->upper_dir_fd >= 0)
                (void) rm_rf_child(hm->upper_dir_fd, hm->work, REMOVE_PHYSICAL);

        hm->resolved = mfree(hm->resolved);
        hm->name = mfree(hm->name);
        hm->parent_fd = safe_close(hm->parent_fd);
        hm->hierarchy_fd = safe_close(hm->hierarchy_fd);
        sub_mount_array_free(hm->submounts, hm->n_submounts);
        hm->submounts = NULL;
        hm->n_submounts = 0;
        hm->base_fd = safe_close(hm->base_fd);
        hm->meta_fd = safe_close(hm->meta_fd);
        hm->import_fd = safe_close(hm->import_fd);
        hm->upper_dir_fd = safe_close(hm->upper_dir_fd);
        hm->upper = mfree(hm->upper);
        hm->work = mfree(hm->work);
        hm->work_dir = mfree(hm->work_dir);
        hm->old_work_dir = mfree(hm->old_work_dir);
        hm->layers = mfree(hm->layers);
        hm->n_layers = 0;
        hm->layer_paths = strv_free(hm->layer_paths);
        hm->options = mfree(hm->options);
}

static DEFINE_ARRAY_FREE_FUNC(hierarchy_merge_array_free, HierarchyMerge, hierarchy_merge_done);

static int hierarchy_merge_add_layer(HierarchyMerge *hm, int fd, const char *path) {
        char *p = NULL;

        assert(hm);
        assert(fd >= 0);

        if (path) {
                p = strdup(path);
                if (!p)
                        return log_oom();

                if (strv_consume(&hm->layer_paths, p) < 0)
                        return log_oom();
        }

        if (!GREEDY_REALLOC(hm->layers, hm->n_layers + 1))
                return log_oom();

        hm->layers[hm->n_layers++] = (OverlayFSLayer) {
                .fd = fd,
                .path = p,
        };

        return 0;
}

static int hierarchy_merge_pin(const Context *c, HierarchyMerge *hm, bool mkdir) {
        int r;

        assert(c);
        assert(hm);
        assert(hm->resolved);

        /* Pins the parent directory and the hierarchy, if it exists. Everything below refers to these
         * inodes, regardless of what happens to the path meanwhile. */

        hm->parent_fd = safe_close(hm->parent_fd);
        hm->hierarchy_fd = safe_close(hm->hierarchy_fd);
        hm->name = mfree(hm->name);

        if (mkdir) {
                r = mkdir_p(hm->resolved, 0755);
                if (r < 0)
                        return log_error_errno(r, "Failed to create hierarchy mount point '%s': %m", hm->resolved);
        }

        r = chase(hm->resolved, c->root, CHASE_PARENT|CHASE_EXTRACT_FILENAME|CHASE_PROHIBIT_SYMLINKS, &hm->name, &hm->parent_fd);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to pin parent directory of '%s': %m", hm->resolved);

        hm->hierarchy_fd = xopenat(hm->parent_fd, hm->name, O_PATH|O_DIRECTORY|O_NOFOLLOW);
        if (hm->hierarchy_fd == -ENOENT) {
                hm->hierarchy_fd = -EBADF;
                return 0;
        }
        if (hm->hierarchy_fd < 0)
                return log_error_errno(hm->hierarchy_fd, "Failed to open '%s': %m", hm->resolved);

        return 1;
}

static int hierarchy_merge_prepare(
                const Context *c,
                HierarchyMerge *hm,
                ExtensionMount *const *extension_mounts,
                size_t n_extension_mounts,
                char **extensions,
                const char *origin_content) {

        _cleanup_free_ char *resolved_mutable_directory = NULL;
        _cleanup_free_ OverlayFSLayer *extension_layers = NULL;
        _cleanup_strv_free_ char **extension_layer_paths = NULL;
        size_t n_extension_layers = 0;
        bool upper_is_hierarchy = false;
        mode_t hierarchy_mode = 0755;
        dev_t backing = 0;
        int r;

        assert(c);
        assert(hm);
        assert(hm->hierarchy);
        assert(extension_mounts || n_extension_mounts == 0);

        /* Collects the layers of the new overlayfs for the hierarchy and creates its metadata. Returns 0 if
         * there is nothing to merge. */

        r = chase(hm->hierarchy, c->root, CHASE_PREFIX_ROOT|CHASE_NONEXISTENT, &hm->resolved, /* ret_fd= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to resolve hierarchy '%s%s': %m", strempty(c->root), hm->hierarchy);

        r = hierarchy_merge_pin(c, hm, /* mkdir= */ false);
        if (r < 0)
                return r;

        FOREACH_ARRAY(e, extension_mounts, n_extension_mounts) {
                _cleanup_free_ char *resolved = NULL;
                const char *fd_path, *p;
                int fd;

                if (extension_mount_dir(*e, hm->hierarchy, &fd, &fd_path) < 0) {
                        log_debug("Hierarchy '%s' in extension '%s' doesn't exist, not merging.", hm->hierarchy, (*e)->name);
                        continue;
                }

                p = path_startswith(hm->hierarchy, fd_path);
                assert(p);

                if (!isempty(p)) {
                        r = chaseat(fd, fd, p, /* flags= */ 0, &resolved, /* ret_fd= */ NULL);
                        if (r == -ENOENT) {
                                log_debug_errno(r, "Hierarchy '%s' in extension '%s' doesn't exist, not merging.", hm->hierarchy, (*e)->name);
                                continue;
                        }
                        if (r < 0)
                                return log_error_errno(r, "Failed to resolve hierarchy '%s' in extension '%s': %m", hm->hierarchy, (*e)->name);
                }

                r = dir_is_empty_at(fd, resolved, /* ignore_hidden_or_backup= */ false);
                if (r < 0)
                        return log_error_errno(r, "Failed to check if hierarchy '%s' in extension '%s' is empty: %m", hm->hierarchy, (*e)->name);
                if (r > 0) {
                        log_debug("Hierarchy '%s' in extension '%s' is empty, not merging.", hm->hierarchy, (*e)->name);
                        continue;
                }

                if (!GREEDY_REALLOC(extension_layers, n_extension_layers + 1))
                        return log_oom();

                extension_layers[n_extension_layers++] = (OverlayFSLayer) {
                        .fd = fd,
                        .path = resolved,
                };

                if (resolved && strv_consume(&extension_layer_paths, TAKE_PTR(resolved)) < 0)
                        return log_oom();
        }

        if (n_extension_layers == 0 && c->mutable == MUTABLE_NO) /* No extension with files in this hierarchy? Then don't do anything. */
                return 0;

        if (hm->hierarchy_fd >= 0) {
                _cleanup_free_ char *dot_dir = NULL;
                struct stat st;

                r = is_our_mount_point_fd(c->image_class, hm->hierarchy_fd, hm->resolved);
                if (r < 0)
                        return r;
                hm->replacing = r > 0;

                /* The submounts get cloned onto the new overlayfs. When replacing our previous overlayfs,
                 * skip its metadata bind mount, the new one gets its own. */
                r = get_sub_mounts(hm->resolved, &hm->submounts, &hm->n_submounts);
                if (r < 0)
                        return log_error_errno(r, "Failed to get submounts for %s: %m", hm->resolved);

                dot_dir = path_join(hm->resolved, image_class_info[c->image_class].dot_directory_name);
                if (!dot_dir)
                        return log_oom();

                if (hm->replacing)
                        FOREACH_ARRAY(m, hm->submounts, hm->n_submounts)
                                if (path_equal(m->path, dot_dir)) {
                                        sub_mount_clear(m);
                                        memmove(m, m + 1, (hm->submounts + hm->n_submounts - m - 1) * sizeof(SubMount));
                                        hm->n_submounts--;
                                        break;
                                }

                if (hm->replacing) {
                        r = read_work_dir_at(c, hm->hierarchy_fd, /* hierarchy_path= */ "", hm->resolved, &hm->old_work_dir);
                        if (r < 0)
                                return r;

                        /* The new overlayfs is assembled while the old one stays in place, hence get what is
                         * beneath the old one without touching it. */
                        r = unpeel_hierarchy(c, hm->resolved, &hm->base_fd);
                        if (r < 0)
                                return r;
                } else {
                        /* A clone without the submounts, which is what overlayfs takes as layer anyway */
                        hm->base_fd = RET_NERRNO(open_tree(hm->hierarchy_fd, "", OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC|AT_EMPTY_PATH));
                        if (hm->base_fd < 0)
                                return log_error_errno(hm->base_fd, "Failed to clone '%s': %m", hm->resolved);
                }

                if (fstat(hm->base_fd, &st) < 0)
                        return log_error_errno(errno, "Failed to stat '%s': %m", hm->resolved);

                hierarchy_mode = st.st_mode & 0777;
        }

        r = resolve_mutable_directory(c, hm->hierarchy, hierarchy_mode, &resolved_mutable_directory);
        if (r < 0)
                return r;

        if (resolved_mutable_directory && hm->hierarchy_fd >= 0) {
                r = path_equal_or_inode_same_full(hm->resolved, resolved_mutable_directory, /* flags= */ 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to check equality of hierarchy %s and its mutable directory %s: %m", hm->resolved, resolved_mutable_directory);
                upper_is_hierarchy = r > 0;
        }

        /* Put the meta path (i.e. our synthesized stuff) at the top of the layer stack */
        hm->meta_fd = make_fsmount(LOG_ERR, image_class_info[c->image_class].short_identifier, "tmpfs", /* flags= */ 0, "mode=0700", /* userns_fd= */ -EBADF);
        if (hm->meta_fd < 0)
                return hm->meta_fd;

        r = mac_selinux_fix_full(hm->meta_fd, /* inode_path= */ NULL, hm->hierarchy, /* flags= */ 0, /* label_context= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to fix SELinux label for metadata of '%s': %m", hm->hierarchy);

        r = hierarchy_merge_add_layer(hm, hm->meta_fd, /* path= */ NULL);
        if (r < 0)
                return r;

        /* If importing the mutable layer and it actually exists and is not the hierarchy itself, add it just
         * below the meta path */
        if (c->mutable == MUTABLE_IMPORT && resolved_mutable_directory) {
                if (upper_is_hierarchy)
                        return log_error_errno(SYNTHETIC_ERRNO(ELOOP), "Not importing mutable directory for hierarchy %s as a lower dir, because it points to the hierarchy itself", hm->hierarchy);

                hm->import_fd = xopenat(AT_FDCWD, resolved_mutable_directory, O_PATH|O_DIRECTORY);
                if (hm->import_fd < 0)
                        return log_error_errno(hm->import_fd, "Failed to open mutable directory '%s': %m", resolved_mutable_directory);
        } else if (c->mutable == MUTABLE_EPHEMERAL_IMPORT) {
                _cleanup_free_ char *dir_name = NULL, *p = NULL, *resolved = NULL;

                dir_name = hierarchy_as_single_path_component(hm->hierarchy);
                if (!dir_name)
                        return log_oom();

                p = path_join(MUTABLE_EXTENSIONS_BASE_DIR, dir_name);
                if (!p)
                        return log_oom();

                r = chase(p, c->root, CHASE_PREFIX_ROOT, &resolved, &hm->import_fd);
                if (r == -ENOENT)
                        log_debug("Mutable directory for %s does not exist, not importing", hm->hierarchy);
                else if (r < 0)
                        return log_error_errno(r, "Failed to resolve mutable directory '%s': %m", p);
                else if (hm->hierarchy_fd >= 0) {
                        r = path_equal_or_inode_same_full(hm->resolved, resolved, /* flags= */ 0);
                        if (r < 0)
                                return log_error_errno(r, "Failed to check equality of hierarchy %s and its mutable directory %s: %m", hm->resolved, resolved);
                        if (r > 0)
                                return log_error_errno(SYNTHETIC_ERRNO(ELOOP), "Not importing mutable directory for hierarchy %s as a lower dir, because it points to the hierarchy itself", hm->hierarchy);
                }
        }
        if (hm->import_fd >= 0) {
                r = hierarchy_merge_add_layer(hm, hm->import_fd, /* path= */ NULL);
                if (r < 0)
                        return r;
        }

        FOREACH_ARRAY(l, extension_layers, n_extension_layers) {
                r = hierarchy_merge_add_layer(hm, l->fd, l->path);
                if (r < 0)
                        return r;
        }

        /* And finally the hierarchy itself at the bottom, unless it is empty or serves as upperdir */
        if (hm->base_fd >= 0) {
                r = dir_is_empty_at(hm->base_fd, /* path= */ NULL, /* ignore_hidden_or_backup= */ false);
                if (r < 0)
                        return log_error_errno(r, "Failed to check if host hierarchy '%s' is empty: %m", hm->resolved);
                if (r > 0)
                        log_debug("Host hierarchy '%s' is empty, will not be used as lower dir.", hm->resolved);
                else if (upper_is_hierarchy && c->mutable != MUTABLE_IMPORT)
                        log_debug("Host hierarchy '%s' will serve as upperdir.", hm->resolved);
                else {
                        r = hierarchy_merge_add_layer(hm, hm->base_fd, /* path= */ NULL);
                        if (r < 0)
                                return r;

                        r = get_block_device_fd(hm->base_fd, &backing);
                        if (r < 0)
                                return log_error_errno(r, "Failed to get block device of '%s': %m", hm->resolved);
                }
        }

        if (IN_SET(c->mutable, MUTABLE_EPHEMERAL, MUTABLE_EPHEMERAL_IMPORT)) {
                r = make_ephemeral_mutable_directory(c, hm->hierarchy, hierarchy_mode, &hm->upper_dir_fd, &hm->upper);
                if (r < 0)
                        return r;

                r = work_dir_name_for_hierarchy(hm->hierarchy, &hm->work);
                if (r < 0)
                        return r;

        } else if (c->mutable != MUTABLE_IMPORT && resolved_mutable_directory) {
                _cleanup_free_ char *parent = NULL;

                /* Require upper dir to be on writable filesystem if it's going to be used as an actual
                 * overlayfs upperdir, instead of a lowerdir as an imported path. */
                r = path_is_read_only_fs(resolved_mutable_directory);
                if (r < 0)
                        return log_error_errno(r, "Failed to determine if mutable directory '%s' is on read-only filesystem: %m", resolved_mutable_directory);
                if (r > 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EROFS), "Can't use '%s' as an upperdir as it is read-only.", resolved_mutable_directory);

                r = path_extract_directory(resolved_mutable_directory, &parent);
                if (r < 0)
                        return log_error_errno(r, "Failed to get parent directory of upperdir '%s': %m", resolved_mutable_directory);

                if (upper_is_hierarchy) {
                        struct stat st_parent, st_base;

                        /* The work dir goes next to the hierarchy, and both must be on the same mount. Take
                         * them from a clone of the mount of the parent directory, which also shows the
                         * hierarchy beneath any overlayfs mounted on it. The mutable directory may be a bind
                         * mount of the hierarchy rather than a symlink to it, so its parent is not
                         * necessarily the parent of the hierarchy. Record the work dir where it really is,
                         * so that unmerging finds and removes it. */
                        parent = mfree(parent);
                        r = path_extract_directory(hm->resolved, &parent);
                        if (r < 0)
                                return log_error_errno(r, "Failed to get parent directory of hierarchy '%s': %m", hm->resolved);

                        if (fstat(hm->parent_fd, &st_parent) < 0)
                                return log_error_errno(errno, "Failed to stat '%s': %m", parent);
                        if (fstat(hm->base_fd, &st_base) < 0)
                                return log_error_errno(errno, "Failed to stat '%s': %m", hm->resolved);
                        if (st_parent.st_dev != st_base.st_dev)
                                return log_error_errno(SYNTHETIC_ERRNO(EXDEV), "Unable to find a suitable workdir location for upperdir '%s' for host hierarchy '%s' - parent directory of the upperdir is in a different filesystem", resolved_mutable_directory, hm->hierarchy);

                        hm->upper_dir_fd = RET_NERRNO(open_tree(hm->parent_fd, "", OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC|AT_EMPTY_PATH));
                        if (hm->upper_dir_fd < 0)
                                return log_error_errno(hm->upper_dir_fd, "Failed to clone '%s': %m", parent);

                        hm->upper = strdup(hm->name);
                        if (!hm->upper)
                                return log_oom();
                } else {
                        r = paths_on_same_fs(resolved_mutable_directory, parent);
                        if (r < 0)
                                return r;
                        if (!r)
                                return log_error_errno(SYNTHETIC_ERRNO(EXDEV), "Unable to find a suitable workdir location for upperdir '%s' for host hierarchy '%s' - parent directory of the upperdir is in a different filesystem", resolved_mutable_directory, hm->hierarchy);

                        hm->upper_dir_fd = xopenat(AT_FDCWD, parent, O_PATH|O_DIRECTORY);
                        if (hm->upper_dir_fd < 0)
                                return log_error_errno(hm->upper_dir_fd, "Failed to open '%s': %m", parent);

                        r = path_extract_filename(resolved_mutable_directory, &hm->upper);
                        if (r < 0)
                                return log_error_errno(r, "Failed to extract file name of '%s': %m", resolved_mutable_directory);
                }

                r = work_dir_name_for_hierarchy(hm->hierarchy, &hm->work);
                if (r < 0)
                        return r;

                hm->work_dir = path_join(parent, hm->work);
                if (!hm->work_dir)
                        return log_oom();
        }

        if (hm->upper_dir_fd >= 0) {
                _cleanup_close_ int work_fd = -EBADF, upper_fd = -EBADF;

                /* The work directory is removed again if we fail (it may be on persistent storage) */
                work_fd = open_mkdir_at(hm->upper_dir_fd, hm->work, O_NOFOLLOW, 0700);
                if (work_fd < 0)
                        return log_error_errno(work_fd, "Failed to create work directory for '%s': %m", hm->hierarchy);

                r = mac_selinux_fix_full(work_fd, /* inode_path= */ NULL, hm->hierarchy, /* flags= */ 0, /* label_context= */ NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to fix SELinux label of work directory for '%s': %m", hm->hierarchy);

                /* Overlayfs merged directory has the same mode as the top layer, which is the upperdir
                 * here. Set it up to the same mode as the unmerged hierarchy. */
                upper_fd = xopenat(hm->upper_dir_fd, hm->upper, O_DIRECTORY|O_NOFOLLOW);
                if (upper_fd < 0)
                        return log_error_errno(upper_fd, "Failed to open upper directory for '%s': %m", hm->hierarchy);

                if (fchmod(upper_fd, hierarchy_mode) < 0)
                        return log_error_errno(errno, "Failed to set permissions of upper directory for '%s' to %04o: %m", hm->hierarchy, hierarchy_mode);
        } else {
                /* Same for the top lowerdir in the read-only case, i.e. the meta path */
                r = fchmod_opath(hm->meta_fd, hierarchy_mode);
                if (r < 0)
                        return log_error_errno(r, "Failed to set permissions of metadata of '%s' to %04o: %m", hm->hierarchy, hierarchy_mode);
        }

        hm->flags = image_class_info[c->image_class].default_mount_flags;
        if (c->noexec >= 0)
                SET_FLAG(hm->flags, MS_NOEXEC, c->noexec);

        const char *mount_options = c->overlayfs_mount_options;
        if (hm->upper_dir_fd >= 0) {
                hm->flags &= ~MS_RDONLY;

                if (!mount_options)
                        mount_options = MUTABLE_EXTENSIONS_MOUNT_OPTIONS;
        }

        hm->options = strdup(strempty(mount_options));
        if (!hm->options)
                return log_oom();

        /* A refresh mounts the new overlay while the old one still uses the same upperdir and overlayfs only
         * permits that with index=off. So append it to the overridden mount options if not set. */
        if (hm->upper_dir_fd >= 0 && !fstab_test_option(mount_options, "index\0") &&
            !strextend_with_separator(&hm->options, ",", "index=off"))
                return log_oom();

        r = store_info_in_meta(c, hm->meta_fd, extensions, origin_content, hm->work_dir, hm->hierarchy, backing);
        if (r < 0)
                return r;

        return 1;
}

static int hierarchy_merge_attach(const Context *c, HierarchyMerge *hm) {
        int r;

        assert(c);
        assert(hm);
        assert(hm->overlay_fd >= 0);

        /* Puts the read-only metadata bind mount and the submounts on top of the new overlayfs, which may
         * still be detached. */

        if (hm->upper_dir_fd >= 0) {
                r = make_meta_read_only(c, hm->overlay_fd, hm->resolved, hm->flags, hm->options);
                if (r < 0)
                        return r;
        }

        return attach_submounts(hm->submounts, hm->n_submounts, hm->resolved, hm->overlay_fd, hm->resolved);
}

static int hierarchy_merge_replace(const Context *c, HierarchyMerge *hm, bool attach_detached) {
        bool old_detached = false, beneath = false;
        int r;

        assert(c);
        assert(hm);
        assert(hm->replacing);

        /* Replaces our previous overlayfs pinned by hierarchy_fd atomically, by mounting the new one beneath
         * it and unmounting it afterwards. If the kernel doesn't support that (added in 6.5), unmount the
         * old one first and mount the new one in its place, with a brief moment where neither is mounted.
         * Unlike mount_exchange_graceful() we go by the pinning fd rather than by path, so that we never
         * unmount something that replaced the old overlayfs meanwhile (a mount stacked on top of it would
         * be hit instead though) and never mount the new one somewhere else than checked, and we don't
         * leave the old overlayfs stacked below the new one in the fallback case, since that would keep its
         * images and work directory referenced. Note that we only ever look at the topmost mount: if
         * there's more than one of our overlayfs stacked here (which can only be the result of somebody
         * bind mounting the hierarchy onto itself), the lower ones remain until the hierarchy is unmerged,
         * and since they share the superblock with the one we replace they lose their work directory when
         * we remove it below. */

        if (c->mount_beneath) {
                log_debug("Mounting new overlayfs beneath '%s'...", hm->resolved);
                r = RET_NERRNO(move_mount(hm->overlay_fd, "", hm->hierarchy_fd, "", MOVE_MOUNT_F_EMPTY_PATH|MOVE_MOUNT_T_EMPTY_PATH|MOVE_MOUNT_BENEATH));
        } else
                r = -EINVAL; /* Behave as if the kernel didn't support it */
        if (r >= 0) {
                hm->mounted = beneath = true;

                /* The new overlayfs is still hidden beneath the old one, hence attach whatever couldn't be
                 * attached while it was detached now, and it all appears at once below. */
                // FIXME: This compatibility code path shall be removed once kernel 6.15
                //        becomes the new minimal baseline
                if (!attach_detached) {
                        r = hierarchy_merge_attach(c, hm);
                        if (r < 0)
                                return log_error_errno(r, "Failed to replace previous merge of '%s', the new one is stacked beneath it now: %m", hm->resolved);
                }

                /* The old overlayfs is the topmost mount now, with nothing stacked on its root, hence the
                 * pinning fd resolves to exactly it. */
                r = umountat_detach_verbose(LOG_DEBUG, hm->hierarchy_fd, /* where= */ "");
                if (r < 0)
                        return log_error_errno(r, "Failed to replace previous merge of '%s', the new one is stacked beneath it now: %m", hm->resolved);

                old_detached = true;
        } else {
                if (r != -EINVAL)
                        return log_error_errno(r, "Failed to mount beneath '%s': %m", hm->resolved);

                // FIXME: This compatibility code path shall be removed once kernel 6.5 becomes the new minimal baseline

                /* Note that we can't mount on top first and detach the old overlayfs afterwards: with the
                 * new tree stacked on its root, the pinning fd would resolve to the new tree. */
                log_debug_errno(r, "Mounting beneath '%s' is not supported, unmounting previous merge first: %m", hm->resolved);

                r = umountat_detach_verbose(LOG_ERR, hm->hierarchy_fd, /* where= */ "");
                if (r < 0)
                        return r;

                old_detached = true;

                /* The pinning fd refers to the detached old overlayfs now, hence go by the parent directory
                 * and the name, which resolves to what became visible below the old overlayfs. */
                r = RET_NERRNO(move_mount(hm->overlay_fd, "", hm->parent_fd, hm->name, MOVE_MOUNT_F_EMPTY_PATH));
                if (r < 0)
                        log_error_errno(r, "Failed to replace previous merge of '%s', the hierarchy is unmerged now, without its submounts: %m", hm->resolved);
                else {
                        hm->mounted = true;

                        if (!attach_detached)
                                r = hierarchy_merge_attach(c, hm);
                }
        }

        /* Now that the old overlayfs is gone, its unique work directory should go, too. A leftover is not
         * worth failing the switch that already happened for. */
        if (old_detached && hm->old_work_dir) {
                int k = rm_rf(hm->old_work_dir, REMOVE_ROOT|REMOVE_MISSING_OK|REMOVE_PHYSICAL);
                if (k < 0)
                        log_warning_errno(k, "Failed to remove '%s', ignoring: %m", hm->old_work_dir);
        }

        if (r < 0)
                return r;

        log_debug("Replaced previous merge of '%s' by mounting %s it.", hm->resolved, beneath ? "beneath" : "in place of");
        return 0;
}

static int hierarchy_merge_finish(const Context *c, HierarchyMerge *hm, bool attach_detached) {
        int r;

        assert(c);
        assert(hm);

        if (hm->n_layers == 0) {
                /* The extensions don't provide this hierarchy (anymore), unmerge it if it is merged. */
                r = unmerge_hierarchy_in_place(c, hm->resolved);
                if (r < 0)
                        return r;

                return 0;
        }

        r = write_dev_file(c, hm->meta_fd, hm->overlay_fd, hm->hierarchy);
        if (r < 0)
                return r;

        /* Since Linux 6.15 mounts can be attached to the overlayfs before it is mounted, so that it appears
         * with everything in place at once. */
        if (attach_detached) {
                r = hierarchy_merge_attach(c, hm);
                if (r < 0)
                        return r;
        }

        if (hm->replacing) {
                r = hierarchy_merge_replace(c, hm, attach_detached);
                if (r < 0)
                        return r;

                log_info("Merged extensions into '%s'.", hm->resolved);
                return 0;
        }

        if (hm->hierarchy_fd < 0) {
                r = hierarchy_merge_pin(c, hm, /* mkdir= */ true);
                if (r < 0)
                        return r;
                if (hm->hierarchy_fd < 0)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "Hierarchy '%s' vanished.", hm->resolved);
        }

        r = RET_NERRNO(move_mount(hm->overlay_fd, "", hm->hierarchy_fd, "", MOVE_MOUNT_F_EMPTY_PATH|MOVE_MOUNT_T_EMPTY_PATH));
        if (r < 0)
                return log_error_errno(r, "Failed to mount overlayfs on '%s': %m", hm->resolved);

        hm->mounted = true;

        // FIXME: This compatibility code path shall be removed once kernel 6.15
        //        becomes the new minimal baseline
        if (!attach_detached) {
                r = hierarchy_merge_attach(c, hm);
                if (r < 0)
                        return r;
        }

        /* Detach the now hidden original submounts, going by fd since they can't be reached by path
         * anymore. (When replacing our previous overlayfs, they go away with it.) */
        FOREACH_ARRAY(m, hm->submounts, hm->n_submounts)
                (void) umountat_detach_verbose(LOG_WARNING, m->original_fd, /* where= */ "");

        log_info("Merged extensions into '%s'.", hm->resolved);
        return 0;
}

static int merge_hierarchies(const Context *c, Hashmap *images) {

        _cleanup_free_ char *host_os_release_id = NULL, *host_os_release_id_like = NULL,
                        *host_os_release_version_id = NULL, *host_os_release_api_level = NULL,
                        *host_os_release_image_id = NULL, *host_os_release_image_version = NULL,
                        *filename = NULL, *old_origin_content = NULL,
                        *extensions_origin_content = NULL;
        _cleanup_strv_free_ char **extensions = NULL, **extensions_v = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *extensions_origin_entries = NULL,
                        *extensions_origin_json = NULL, *mutable_dir_entries = NULL;
        _cleanup_(host_properties_done) HostProperties host = {};
        ExtensionMount *extension_mounts = NULL;
        HierarchyMerge *merges = NULL;
        size_t n_extensions = 0, n_extension_mounts = 0, n_merges = 0;
        unsigned n_ignored = 0;
        Image *img;
        int r;

        assert(c);

        CLEANUP_ARRAY(extension_mounts, n_extension_mounts, extension_mount_array_free);
        CLEANUP_ARRAY(merges, n_merges, hierarchy_merge_array_free);

        /* Note that everything is assembled as detached mounts, which nobody else can see and which go away
         * automatically when we are done, until the overlayfs mounts are put in place at the very end. */

        mac_selinux_init();

        /* Acquire host OS release info, so that we can compare it with the extension's data */
        r = parse_os_release(
                        c->root,
                        "ID", &host_os_release_id,
                        "ID_LIKE", &host_os_release_id_like,
                        "VERSION_ID", &host_os_release_version_id,
                        image_class_info[c->image_class].level_env, &host_os_release_api_level,
                        "IMAGE_ID", &host_os_release_image_id,
                        "IMAGE_VERSION", &host_os_release_image_version);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire 'os-release' data of OS tree '%s': %m", empty_to_root(c->root));
        if (isempty(host_os_release_id))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "'ID' field not found or empty in 'os-release' data of OS tree '%s'.",
                                       empty_to_root(c->root));

        /* Let's now mount all images, as detached mounts */
        HASHMAP_FOREACH(img, images) {
                _cleanup_(extension_mount_done) ExtensionMount em = EXTENSION_MOUNT_NULL;
                _cleanup_free_ char *path_without_root = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *verity_hash = NULL;

                em.name = strdup(img->name);
                if (!em.name)
                        return log_oom();

                switch (img->type) {
                case IMAGE_DIRECTORY:
                case IMAGE_SUBVOLUME:

                        /* Overlayfs makes the layers read-only itself, hence no need for a bind mount */
                        em.root_fd = xopenat(AT_FDCWD, img->path, O_PATH|O_DIRECTORY);
                        if (em.root_fd < 0)
                                return log_error_errno(em.root_fd, "Failed to open '%s': %m", img->path);

                        if (!c->force) {
                                r = extension_has_forbidden_content_at(em.root_fd, "/");
                                if (r < 0)
                                        return log_error_errno(r, "Failed to check extension '%s' for forbidden content: %m", img->name);
                                if (r > 0) {
                                        n_ignored++;
                                        continue;
                                }
                        }

                        break;

                case IMAGE_RAW:
                case IMAGE_BLOCK: {
                        _cleanup_(dissected_image_unrefp) DissectedImage *m = NULL;
                        _cleanup_(loop_device_unrefp) LoopDevice *d = NULL;
                        _cleanup_(verity_settings_done) VeritySettings verity_settings = VERITY_SETTINGS_DEFAULT;
                        DissectImageFlags flags =
                                DISSECT_IMAGE_READ_ONLY |
                                DISSECT_IMAGE_GENERIC_ROOT |
                                DISSECT_IMAGE_REQUIRE_ROOT |
                                DISSECT_IMAGE_MOUNT_ROOT_ONLY |
                                DISSECT_IMAGE_USR_NO_ROOT |
                                DISSECT_IMAGE_ADD_PARTITION_DEVICES |
                                DISSECT_IMAGE_PIN_PARTITION_DEVICES |
                                DISSECT_IMAGE_ALLOW_USERSPACE_VERITY |
                                DISSECT_IMAGE_TPM2_UNLOCK;

                        r = verity_settings_load(&verity_settings, img->path, /* root_hash_path= */ NULL, /* root_hash_sig_path= */ NULL);
                        if (r < 0)
                                return log_error_errno(r, "Failed to read verity artifacts for %s: %m", img->path);

                        if (verity_settings.data_path)
                                flags |= DISSECT_IMAGE_NO_PARTITION_TABLE;

                        r = loop_device_make_by_path(
                                        img->path,
                                        O_RDONLY,
                                        /* sector_size= */ UINT32_MAX,
                                        FLAGS_SET(flags, DISSECT_IMAGE_NO_PARTITION_TABLE) ? 0 : LO_FLAGS_PARTSCAN,
                                        LOCK_SH,
                                        &d);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set up loopback device for %s: %m", img->path);

                        r = dissect_loop_device_and_warn(
                                        d,
                                        &verity_settings,
                                        /* mount_options= */ NULL,
                                        pick_image_policy(c, img),
                                        /* image_filter= */ NULL,
                                        flags,
                                        &m);
                        if (r < 0)
                                return r;

                        /* Do not use the image name derived from the backing file of the loop device */
                        r = free_and_strdup(&m->image_name, img->name);
                        if (r < 0)
                                return r;

                        r = dissected_image_load_verity_sig_partition(
                                        m,
                                        d->fd,
                                        &verity_settings);
                        if (r < 0)
                                return r;

                        r = dissected_image_guess_verity_roothash(
                                        m,
                                        &verity_settings);
                        if (r < 0)
                                return r;

                        if (iovec_is_set(&verity_settings.root_hash)) {
                                r = sd_json_variant_new_hex(&verity_hash, verity_settings.root_hash.iov_base, verity_settings.root_hash.iov_len);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to create origin verity entry for '%s': %m", img->name);
                        }

                        r = dissected_image_decrypt(m, c->root, /* passphrase= */ NULL, &verity_settings, pick_image_policy(c, img), flags);
                        if (r < 0)
                                return r;

                        r = dissected_image_mount_and_warn(
                                        m,
                                        /* where= */ NULL,
                                        /* uid_shift= */ UID_INVALID,
                                        /* uid_range= */ UID_INVALID,
                                        /* userns_fd= */ -EBADF,
                                        flags);
                        if (r < 0)
                                return r;

                        em.root_fd = TAKE_FD(m->partitions[PARTITION_ROOT].fsmount_fd);
                        em.usr_fd = TAKE_FD(m->partitions[PARTITION_USR].fsmount_fd);

                        r = dissected_image_relinquish(m);
                        if (r < 0)
                                return log_error_errno(r, "Failed to relinquish DM and loopback block devices: %m");

                        if (!c->force) {
                                r = extension_mount_is_valid(&em);
                                if (r < 0)
                                        return r;
                                if (r == 0) {
                                        n_ignored++;
                                        continue;
                                }
                        }

                        break;
                }
                default:
                        assert_not_reached();
                }

                if (c->force)
                        log_debug("Force mode enabled, skipping version validation.");
                else {
                        bool is_initrd;
                        r = chase_and_access("/etc/initrd-release", c->root, CHASE_PREFIX_ROOT, F_OK, /* ret_path= */ NULL);
                        if (r < 0 && r != -ENOENT)
                                return log_error_errno(r, "Failed to check for /etc/initrd-release: %m");
                        is_initrd = r >= 0;

                        r = extension_release_validate(
                                        img->name,
                                        host_os_release_id,
                                        host_os_release_id_like,
                                        host_os_release_version_id,
                                        host_os_release_api_level,
                                        host_os_release_image_id,
                                        host_os_release_image_version,
                                        is_initrd ? "initrd" : "system",
                                        image_extension_release(img, c->image_class),
                                        c->image_class);
                        if (r < 0)
                                return r;
                        if (r == 0) {
                                n_ignored++;
                                continue;
                        }

                        /* Check MATCH_HOSTNAME= and friends, and the "user.uapi.match_…" xattrs of the
                         * image */
                        unsigned contradicting = 0;
                        r = extension_match_host(
                                        img->name,
                                        img->path,
                                        image_extension_release(img, c->image_class),
                                        &host,
                                        empty_to_null(c->root),
                                        &contradicting);
                        if (r < 0)
                                return log_error_errno(r, "Failed to check whether extension '%s' is suitable for this system: %m", img->name);

                        for (XAttrMatch m = 0; m < _XATTR_MATCH_MAX; m++) {
                                if (!FLAGS_SET(contradicting, XATTR_MATCH_MASK(m)))
                                        continue;

                                const char *field = extension_release_match_field_to_string(m);
                                log_warning("Extended attribute 'user.%s' of extension '%s' contradicts %s=%s in its extension-release file, honouring both.",
                                            xattr_match_to_xattr_name(m),
                                            img->name,
                                            field,
                                            strna(strv_env_pairs_get(image_extension_release(img, c->image_class), field)));
                        }

                        if (r == 0) {
                                n_ignored++;
                                continue;
                        }
                }

                /* Nice! This one is an extension we want. */
                r = strv_extend(&extensions, img->name);
                if (r < 0)
                        return log_oom();

                /* Also get the absolute file name with version info for logging. */
                r = path_extract_filename(img->path, &filename);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0)
                        return log_error_errno(r, "Failed to extract filename from '%s': %m", img->path);

                r = strv_extend(&extensions_v, filename);
                if (r < 0)
                        return log_oom();

                /* Encode extension image origin to check if we can skip the refresh.
                 * It can also be used to provide more detail in "systemd-sysext status". */

                if (!isempty(c->root)) {
                        const char *without_root = NULL;
                        without_root = path_startswith(img->path, c->root);
                        if (!isempty(without_root)) {
                                path_without_root = strjoin("/", without_root);
                                if (!path_without_root)
                                        return log_oom();
                        }
                }
                if (!path_without_root) {
                        path_without_root = strdup(img->path);
                        if (!path_without_root)
                                return log_oom();
                }

                /* The verity hash is not available for all extension types, thus, but only as fallback,
                 * also include data to check for file/directory replacements through a file handle and
                 * unique mount ID (or inode and mount ID as fallback).
                 * A unique mount ID is best because st_dev gets reused too easily, e.g., by a loop dev
                 * mount. For the mount ID to be valid it has to be resolved before we enter the new mount
                 * namespace. Thus, here it wouldn't work and so instead it gets provided by the image
                 * dissect logic and handed over to this subprocess we are in.
                 * Online modification is not well supported with overlay mounts, so we don't do a file
                 * checksum nor do we recurse into a directory to look for touched files. If users want
                 * modifications to be picked up, they need to set the --always-refresh=yes flag (as will be
                 * printed out). */

                _cleanup_(sd_json_variant_unrefp) sd_json_variant *origin_entry = NULL;

                /* We suppress inclusion of weak identifiers when a strong one is there so that, e.g.,
                 * a confext image stored on /usr gets identified only by the verity hash instead of also
                 * the mount ID because that changes when a sysext overlay mount appears but since the
                 * verity hash is the same for the confext it can actually be reused. */
                r = sd_json_buildo(&origin_entry,
                                   SD_JSON_BUILD_PAIR_STRING("path", path_without_root),
                                   SD_JSON_BUILD_PAIR_CONDITION(!!verity_hash, "verityHash", SD_JSON_BUILD_VARIANT(verity_hash)),
                                   SD_JSON_BUILD_PAIR_CONDITION(!verity_hash, "onMountId", SD_JSON_BUILD_UNSIGNED(img->on_mount_id)),
                                   SD_JSON_BUILD_PAIR_CONDITION(!verity_hash && !!img->fh, "fileHandle",
                                                                SD_JSON_BUILD_OBJECT(SD_JSON_BUILD_PAIR_INTEGER("type", img->fh->handle_type),
                                                                                     SD_JSON_BUILD_PAIR_HEX("handle", img->fh->f_handle,
                                                                                                            img->fh->handle_bytes))),
                                   SD_JSON_BUILD_PAIR_CONDITION(!verity_hash && !img->fh, "inode", SD_JSON_BUILD_UNSIGNED(img->inode)),
                                   SD_JSON_BUILD_PAIR_CONDITION(!verity_hash, "crtime", SD_JSON_BUILD_UNSIGNED(img->crtime)),
                                   SD_JSON_BUILD_PAIR_CONDITION(!verity_hash, "mtime", SD_JSON_BUILD_UNSIGNED(img->mtime)));
                if (r < 0)
                        return log_error_errno(r, "Failed to create origin entry for '%s': %m", img->name);

                r = sd_json_variant_set_field(&extensions_origin_entries, img->name, origin_entry);
                if (r < 0)
                        return log_error_errno(r, "Failed to add origin entry for '%s': %m", img->name);

                if (!GREEDY_REALLOC(extension_mounts, n_extension_mounts + 1))
                        return log_oom();

                extension_mounts[n_extension_mounts++] = TAKE_GENERIC(em, ExtensionMount, EXTENSION_MOUNT_NULL);
                n_extensions++;
        }

        /* Nothing left? Then shortcut things */
        if (n_extensions == 0 && c->mutable == MUTABLE_NO) {
                if (n_ignored > 0)
                        log_info("No suitable extensions found (%u ignored due to incompatible image(s)).", n_ignored);
                else
                        log_info("No extensions found.");
                return MERGE_NOTHING_FOUND;
        }

        /* Order by version sort with strverscmp_improved() */
        typesafe_qsort(extensions, n_extensions, strverscmp_improvedp);
        typesafe_qsort(extensions_v, n_extensions, strverscmp_improvedp);

        STRV_FOREACH(h, c->hierarchies) {
                _cleanup_free_ char *f = NULL, *buf = NULL, *resolved = NULL, *mutable_directory_without_root = NULL,
                        *resolved_mutable_directory = NULL;

                /* The origin file includes the backing directories for mutable overlays. */
                r = hierarchy_mutable_directory(c, *h, &resolved_mutable_directory);
                if (r < 0)
                        return r;

                if (resolved_mutable_directory && !isempty(c->root)) {
                        const char *without_root = NULL;
                        without_root = path_startswith(resolved_mutable_directory, c->root);
                        if (!isempty(without_root)) {
                                mutable_directory_without_root = strjoin("/", without_root);
                                if (!mutable_directory_without_root)
                                        return log_oom();
                        }
                }
                if (!mutable_directory_without_root && resolved_mutable_directory) {
                        mutable_directory_without_root = strdup(resolved_mutable_directory);
                        if (!mutable_directory_without_root)
                                return log_oom();
                }

                if (mutable_directory_without_root) {
                        r = sd_json_variant_set_field_string(&mutable_dir_entries, *h, mutable_directory_without_root);
                        if (r < 0)
                                return log_error_errno(r, "Failed to add mutable directory to origin JSON entry: %m");
                }

                /* Find existing origin file for comparison. */
                r = chase(*h, c->root, CHASE_PREFIX_ROOT|CHASE_NONEXISTENT, &resolved, /* ret_fd= */ NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to resolve hierarchy '%s%s': %m", strempty(c->root), *h);

                f = path_join(resolved, image_class_info[c->image_class].dot_directory_name, "origin");
                if (!f)
                        return log_oom();

                r = is_our_mount_point(c->image_class, resolved);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                /* TODO: The origin of the first merged hierarchy stands for all of them. If a refresh failed
                 * after replacing some hierarchies, the others still carry the previous extensions, and the
                 * next refresh skips them as unchanged until --always-refresh=yes is used or they are
                 * unmerged. Compare the origin of every merged hierarchy instead. */
                if (old_origin_content)
                        continue;

                r = read_full_file(f, &buf, /* ret_size= */ NULL);
                if (r < 0) {
                        log_debug_errno(r, "Failed to open '%s', continuing search: %m", f);
                        continue;
                }

                old_origin_content = TAKE_PTR(buf);
        }

        r = sd_json_buildo(&extensions_origin_json,
                           SD_JSON_BUILD_PAIR_OBJECT("mutable",
                                                     SD_JSON_BUILD_PAIR_STRING("mode", mutable_mode_to_string(c->mutable)),
                                                     SD_JSON_BUILD_PAIR_CONDITION(!!mutable_dir_entries,
                                                                                  "mutableDirs",
                                                                                  SD_JSON_BUILD_VARIANT(mutable_dir_entries))),
                           SD_JSON_BUILD_PAIR_CONDITION(!isempty(c->overlayfs_mount_options),
                                                        "mountOptions",
                                                        SD_JSON_BUILD_STRING(c->overlayfs_mount_options)),
                           SD_JSON_BUILD_PAIR_CONDITION(!!extensions_origin_entries,
                                                        "extensions",
                                                        SD_JSON_BUILD_VARIANT(extensions_origin_entries)));
        if (r < 0)
                return log_error_errno(r, "Failed to create extensions origin JSON object: %m");

        r = sd_json_variant_format(extensions_origin_json, SD_JSON_FORMAT_PRETTY|SD_JSON_FORMAT_NEWLINE, &extensions_origin_content);
        if (r < 0)
                return log_error_errno(r, "Failed to format extension origin as JSON: %m");

        log_debug("New extension origin entry (unordered):\n%s\n", extensions_origin_content);

        if (old_origin_content) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *old_origin_json = NULL;

                log_debug("Old extension origin entry (unordered):\n%s\n", old_origin_content);
                r = sd_json_parse(old_origin_content, /* flags= */ 0, &old_origin_json, /* reterr_line= */ NULL, /* reterr_column= */ NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse existing extension origin content: %m");

                /* This works well with unordered entries. */
                if (sd_json_variant_equal(extensions_origin_json, old_origin_json)) {
                        if (!c->always_refresh) {
                                /* This only happens during refresh, not merge, thus talk about refresh here. */
                                log_info("Skipping extension refresh because no change was found, use --always-refresh=yes to always do a refresh.");
                                return MERGE_SKIP_REFRESH;
                        }

                        log_debug("No change found based on origin entry but continuing as requested by --always-refresh=yes.");
                } else
                        log_debug("Found changes based on origin entry, continuing with the refresh.");
        }

        if (n_extensions == 0) {
                assert(c->mutable != MUTABLE_NO);
                log_info("No extensions found, proceeding in mutable mode.");
        } else {
                _cleanup_free_ char *buf = strv_join(extensions_v, "', '");
                if (!buf)
                        return log_oom();

                log_info("Using extensions '%s'.", buf);
        }

        /* The extensions in reverse order, i.e. the topmost layer first */
        _cleanup_free_ ExtensionMount **ordered = new0(ExtensionMount*, n_extensions + 1);
        if (!ordered)
                return log_oom();

        for (size_t k = 0; k < n_extensions; k++)
                assert_se(ordered[k] = extension_mount_find(extension_mounts, n_extension_mounts, extensions[n_extensions - 1 - k]));

        merges = new(HierarchyMerge, MAX(strv_length(c->hierarchies), 1u));
        if (!merges)
                return log_oom();

        STRV_FOREACH(h, c->hierarchies) {
                HierarchyMerge *hm = merges + n_merges++;

                *hm = HIERARCHY_MERGE_NULL;
                hm->hierarchy = *h;

                r = hierarchy_merge_prepare(c, hm, ordered, n_extensions, extensions, extensions_origin_content);
                if (r < 0)
                        return r;
        }

        _cleanup_free_ OverlayFSSpec *specs = new(OverlayFSSpec, MAX(n_merges, 1u));
        _cleanup_free_ int *overlay_fds = new(int, MAX(n_merges, 1u));
        size_t n_specs = 0;
        if (!specs || !overlay_fds)
                return log_oom();

        FOREACH_ARRAY(hm, merges, n_merges) {
                if (hm->n_layers == 0)
                        continue;

                specs[n_specs++] = (OverlayFSSpec) {
                        .source = image_class_info[c->image_class].short_identifier,
                        .layers = hm->layers,
                        .n_layers = hm->n_layers,
                        .upper_dir_fd = hm->upper_dir_fd,
                        .upper = hm->upper,
                        .work = hm->work,
                        .flags = hm->flags,
                        .options = hm->options,
                };
        }

        r = overlayfs_make_mounts(specs, n_specs, overlay_fds);
        if (r < 0)
                return log_error_errno(r, "Failed to create overlayfs mounts: %m");
        bool attach_detached = r > 0;

        size_t k = 0;
        FOREACH_ARRAY(hm, merges, n_merges)
                if (hm->n_layers > 0)
                        hm->overlay_fd = overlay_fds[k++];

        /* And move them all into place. This is where things appear in the host namespace */
        FOREACH_ARRAY(hm, merges, n_merges) {
                r = hierarchy_merge_finish(c, hm, attach_detached);
                if (r < 0)
                        return r;
        }

        return MERGE_MOUNTED;
}

static int merge(const Context *c, Hashmap *images) {
        int r;

        assert(c);

        (void) dlopen_cryptsetup(LOG_DEBUG);
        (void) dlopen_libblkid(LOG_DEBUG);
        (void) dlopen_libmount(LOG_DEBUG);

        r = merge_hierarchies(c, images);
        if (r < 0)
                return r;
        if (r == MERGE_NOTHING_FOUND)
                return 0; /* Tell refresh to unmount */
        if (r == MERGE_SKIP_REFRESH)
                return 1; /* Same return code as below when we have merged new */

        _cleanup_set_free_ Set *units_to_restart = NULL, *units_to_reload_or_restart = NULL;
        bool need_to_reload;
        r = get_extension_release_metadata(c, &need_to_reload, &units_to_restart, &units_to_reload_or_restart);
        if (r < 0)
                return r;
        if (need_to_reload) {
                r = daemon_reload();
                if (r < 0)
                        return r;
        }

        /* The sets will be empty when opted out */
        r = restart_units(units_to_restart, units_to_reload_or_restart);
        if (r < 0)
                return r;

        return 1;
}

VERB_DEFAULT_NOARG(verb_status, "status", "Show current merge status (default)");
static int verb_status(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(context_done) Context c = CONTEXT_NULL;
        _cleanup_(table_unrefp) Table *t = NULL;
        int r, ret = 0;

        r = context_from_cmdline(&c, arg_image_class);
        if (r < 0)
                return r;

        t = table_new("hierarchy", "extensions", "since");
        if (!t)
                return log_oom();

        table_set_ersatz_string(t, TABLE_ERSATZ_DASH);

        STRV_FOREACH(p, c.hierarchies) {
                _cleanup_free_ char *resolved = NULL, *f = NULL, *buf = NULL;
                _cleanup_strv_free_ char **l = NULL;
                struct stat st;

                r = chase(*p, c.root, CHASE_PREFIX_ROOT, &resolved, /* ret_fd= */ NULL);
                if (r == -ENOENT) {
                        log_debug_errno(r, "Hierarchy '%s%s' does not exist, ignoring.", strempty(c.root), *p);
                        continue;
                }
                if (r < 0) {
                        log_error_errno(r, "Failed to resolve path to hierarchy '%s%s': %m", strempty(c.root), *p);
                        goto inner_fail;
                }

                r = is_our_mount_point(c.image_class, resolved);
                if (r < 0)
                        goto inner_fail;
                if (r == 0) {
                        r = table_add_many(
                                        t,
                                        TABLE_PATH, *p,
                                        TABLE_STRV, STRV_EMPTY,
                                        TABLE_EMPTY);
                        if (r < 0)
                                return table_log_add_error(r);

                        continue;
                }

                f = path_join(resolved, image_class_info[c.image_class].dot_directory_name, image_class_info[c.image_class].short_identifier_plural);
                if (!f)
                        return log_oom();

                r = read_full_file(f, &buf, /* ret_size= */ NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to open '%s': %m", f);

                l = strv_split_newlines(buf);
                if (!l)
                        return log_oom();

                if (stat(*p, &st) < 0)
                        return log_error_errno(errno, "Failed to stat() '%s': %m", *p);

                r = table_add_many(
                                t,
                                TABLE_PATH, *p,
                                TABLE_STRV, l,
                                TABLE_TIMESTAMP, timespec_load(&st.st_mtim));
                if (r < 0)
                        return table_log_add_error(r);

                continue;

        inner_fail:
                if (ret == 0)
                        ret = r;
        }

        (void) table_set_sort(t, (size_t) 0);

        r = table_print_with_pager(t, arg_json_format_flags, arg_pager_flags, arg_legend);
        if (r < 0)
                return r;

        return ret;
}

static int image_discover_and_read_metadata(const Context *c, Hashmap **ret_images) {
        _cleanup_hashmap_free_ Hashmap *images = NULL;
        Image *img;
        int r;

        assert(c);
        assert(ret_images);

        r = image_discover(RUNTIME_SCOPE_SYSTEM, c->image_class, c->root, &images);
        if (r < 0)
                return log_error_errno(r, "Failed to discover images: %m");

        HASHMAP_FOREACH(img, images) {
                r = image_read_metadata(img, c->root, image_class_info[c->image_class].default_image_policy, RUNTIME_SCOPE_SYSTEM, DISSECT_IMAGE_TPM2_UNLOCK);
                if (r < 0)
                        return log_error_errno(r, "Failed to read metadata for image %s: %m", img->name);
        }

        *ret_images = TAKE_PTR(images);

        return 0;
}

static int look_for_merged_hierarchies(const Context *c, const char **ret_which) {
        int r;

        assert(c);
        assert(ret_which);

        /* In merge mode fail if things are already merged. (In --refresh mode below we'll unmerge if we find
         * things are already merged...) */
        STRV_FOREACH(p, c->hierarchies) {
                _cleanup_free_ char *resolved = NULL;

                r = chase(*p, c->root, CHASE_PREFIX_ROOT, &resolved, /* ret_fd= */ NULL);
                if (r == -ENOENT) {
                        log_debug_errno(r, "Hierarchy '%s%s' does not exist, ignoring.", strempty(c->root), *p);
                        continue;
                }
                if (r < 0)
                        return log_error_errno(r, "Failed to resolve path to hierarchy '%s%s': %m", strempty(c->root), *p);

                r = is_our_mount_point(c->image_class, resolved);
                if (r < 0)
                        return r;
                if (r > 0) {
                        *ret_which = *p;
                        return 1;
                }
        }

        *ret_which = NULL;
        return 0;
}

VERB_NOARG(verb_merge, "merge", "Merge extensions into relevant hierarchies");
static int verb_merge(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(context_done) Context c = CONTEXT_NULL;
        _cleanup_hashmap_free_ Hashmap *images = NULL;
        const char *which;
        int r;

        r = have_effective_cap(CAP_SYS_ADMIN);
        if (r < 0)
                return log_error_errno(r, "Failed to check if we have enough privileges: %m");
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EPERM), "Need to be privileged.");

        r = context_from_cmdline(&c, arg_image_class);
        if (r < 0)
                return r;

        r = image_discover_and_read_metadata(&c, &images);
        if (r < 0)
                return r;

        r = look_for_merged_hierarchies(&c, &which);
        if (r < 0)
                return r;
        if (r > 0)
                return log_error_errno(SYNTHETIC_ERRNO(EBUSY), "Hierarchy '%s' is already merged.", which);

        return merge(&c, images);
}

typedef struct MethodMergeParameters {
        const char *class;
        int force;
        int no_reload;
        int always_refresh;
        int noexec;
} MethodMergeParameters;

static int parse_merge_parameters(sd_varlink *link, sd_json_variant *parameters, MethodMergeParameters *p) {

        static const sd_json_dispatch_field dispatch_table[] = {
                { "class",         SD_JSON_VARIANT_STRING,  sd_json_dispatch_const_string, offsetof(MethodMergeParameters, class),          0 },
                { "force",         SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_tristate,     offsetof(MethodMergeParameters, force),          0 },
                { "noReload",      SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_tristate,     offsetof(MethodMergeParameters, no_reload),      0 },
                { "alwaysRefresh", SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_tristate,     offsetof(MethodMergeParameters, always_refresh), 0 },
                { "noexec",        SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_tristate,     offsetof(MethodMergeParameters, noexec),         0 },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        assert(link);
        assert(parameters);
        assert(p);

        return sd_varlink_dispatch(link, parameters, dispatch_table, p);
}

static int vl_method_merge(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Hashmap **polkit_registry = ASSERT_PTR(userdata);
        _cleanup_(context_done) Context c = CONTEXT_NULL;
        _cleanup_hashmap_free_ Hashmap *images = NULL;
        MethodMergeParameters p = {
                .force = -1,
                .no_reload = -1,
                .always_refresh = -1,
                .noexec = -1,
        };
        ImageClass image_class = arg_image_class;
        int r;

        assert(link);

        r = parse_merge_parameters(link, parameters, &p);
        if (r != 0)
                return r;

        r = parse_image_class_parameter(link, p.class, &image_class);
        if (r < 0)
                return r;

        r = context_from_cmdline(&c, image_class);
        if (r < 0)
                return r;

        if (p.force >= 0)
                c.force = p.force;
        if (p.no_reload >= 0)
                c.no_reload = p.no_reload;
        if (p.always_refresh >= 0)
                c.always_refresh = p.always_refresh;
        if (p.noexec >= 0)
                c.noexec = p.noexec;

        r = varlink_verify_polkit_async(
                        link,
                        /* bus= */ NULL,
                        image_class_info[c.image_class].polkit_rw_action_id,
                        (const char**) STRV_MAKE(
                                "verb", "merge",
                                "force", one_zero(c.force),
                                "noReload", one_zero(c.no_reload),
                                "noexec", one_zero(c.noexec > 0)),
                        polkit_registry);
        if (r <= 0)
                return r;

        r = image_discover_and_read_metadata(&c, &images);
        if (r < 0)
                return r;

        const char *which;
        r = look_for_merged_hierarchies(&c, &which);
        if (r < 0)
                return r;
        if (r > 0)
                return sd_varlink_errorbo(link, "io.systemd.sysext.AlreadyMerged", SD_JSON_BUILD_PAIR_STRING("hierarchy", which));

        r = merge(&c, images);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, /* parameters= */ NULL);
}

VERB_NOARG(verb_unmerge, "unmerge", "Unmerge extensions from relevant hierarchies");
static int verb_unmerge(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(context_done) Context c = CONTEXT_NULL;
        int r;

        r = have_effective_cap(CAP_SYS_ADMIN);
        if (r < 0)
                return log_error_errno(r, "Failed to check if we have enough privileges: %m");
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EPERM), "Need to be privileged.");

        r = context_from_cmdline(&c, arg_image_class);
        if (r < 0)
                return r;

        return unmerge(&c);
}

typedef struct MethodUnmergeParameters {
        const char *class;
        int no_reload;
} MethodUnmergeParameters;

static int vl_method_unmerge(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {

        static const sd_json_dispatch_field dispatch_table[] = {
                { "class",    SD_JSON_VARIANT_STRING,  sd_json_dispatch_const_string, offsetof(MethodUnmergeParameters, class),     0 },
                { "noReload", SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool,      offsetof(MethodUnmergeParameters, no_reload), 0 },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };
        MethodUnmergeParameters p = {
                .no_reload = -1,
        };
        Hashmap **polkit_registry = ASSERT_PTR(userdata);
        _cleanup_(context_done) Context c = CONTEXT_NULL;
        ImageClass image_class = arg_image_class;
        int r;

        assert(link);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        r = parse_image_class_parameter(link, p.class, &image_class);
        if (r < 0)
                return r;

        r = context_from_cmdline(&c, image_class);
        if (r < 0)
                return r;

        if (p.no_reload >= 0)
                c.no_reload = p.no_reload;

        r = varlink_verify_polkit_async(
                        link,
                        /* bus= */ NULL,
                        image_class_info[c.image_class].polkit_rw_action_id,
                        (const char**) STRV_MAKE(
                                "verb", "unmerge",
                                "noReload", one_zero(c.no_reload)),
                        polkit_registry);
        if (r <= 0)
                return r;

        r = unmerge(&c);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, /* parameters= */ NULL);
}

static int refresh(const Context *c) {

        _cleanup_hashmap_free_ Hashmap *images = NULL;
        int r;

        assert(c);

        r = image_discover_and_read_metadata(c, &images);
        if (r < 0)
                return r;

        /* Returns > 0 if it did something, i.e. a new overlayfs is mounted now. When it does so it
         * implicitly unmounts any overlayfs placed there before. It also returns == 1 if there were
         * no changes found to apply and the mount stays intact. Returns == 0 if it did nothing, i.e. no
         * extension images found. In this case the old overlayfs remains in place if there was one. */
        r = merge(c, images);
        if (r < 0)
                return r;
        if (r == 0) /* No images found? Then unmerge. The goal of --refresh is after all that after having
                     * called there's a guarantee that the merge status matches the installed extensions. */
                r = unmerge(c);

        /* Net result here is that:
         *
         * 1. If an overlayfs was mounted before and no extensions exist anymore, we'll have unmerged things.
         *
         * 2. If an overlayfs was mounted before, and there are still extensions installed' we'll have
         *    unmerged and then merged things again or we have skipped the refresh because no changes
         *    were found.
         *
         * 3. If an overlayfs so far wasn't mounted, and there are extensions installed, we'll have it
         *    mounted now.
         *
         * 4. If there was no overlayfs mount so far, and no extensions installed, we implement a NOP.
         */

        return r;
}

VERB_NOARG(verb_refresh, "refresh", "Unmerge/merge extensions again");
static int verb_refresh(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(context_done) Context c = CONTEXT_NULL;
        int r;

        r = have_effective_cap(CAP_SYS_ADMIN);
        if (r < 0)
                return log_error_errno(r, "Failed to check if we have enough privileges: %m");
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EPERM), "Need to be privileged.");

        r = context_from_cmdline(&c, arg_image_class);
        if (r < 0)
                return r;

        return refresh(&c);
}

static int vl_method_refresh(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {

        _cleanup_(context_done) Context c = CONTEXT_NULL;
        MethodMergeParameters p = {
                .force = -1,
                .no_reload = -1,
                .always_refresh = -1,
                .noexec = -1,
        };
        Hashmap **polkit_registry = ASSERT_PTR(userdata);
        ImageClass image_class = arg_image_class;
        int r;

        assert(link);

        r = parse_merge_parameters(link, parameters, &p);
        if (r != 0)
                return r;

        r = parse_image_class_parameter(link, p.class, &image_class);
        if (r < 0)
                return r;

        r = context_from_cmdline(&c, image_class);
        if (r < 0)
                return r;

        if (p.force >= 0)
                c.force = p.force;
        if (p.no_reload >= 0)
                c.no_reload = p.no_reload;
        if (p.always_refresh >= 0)
                c.always_refresh = p.always_refresh;
        if (p.noexec >= 0)
                c.noexec = p.noexec;

        r = varlink_verify_polkit_async(
                        link,
                        /* bus= */ NULL,
                        image_class_info[c.image_class].polkit_rw_action_id,
                        (const char**) STRV_MAKE(
                                "verb", "refresh",
                                "force", one_zero(c.force),
                                "noReload", one_zero(c.no_reload),
                                "noexec", one_zero(c.noexec > 0)),
                        polkit_registry);
        if (r <= 0)
                return r;

        r = refresh(&c);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, /* parameters= */ NULL);
}

static int refresh_class(ImageClass image_class) {
        _cleanup_(context_done) Context c = CONTEXT_NULL;
        int r;

        /* The sysupdate notification service is systemd-sysext, but it refreshes both sysexts and
         * confexts. Apply the relevant class-specific environment and configuration for each refresh. */
        r = context_from_cmdline(&c, image_class);
        if (r < 0)
                return r;

        return refresh(&c);
}

static int vl_method_on_completed_update(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        int r;

        assert(link);

        /* Only honour update notifications if they come from root */
        r = varlink_check_privileged_peer(link);
        if (r < 0)
                return r;

        /* Triggered by systemd-sysupdate after an update completed. We deliberately ignore all parameters
         * (we don't even dispatch them). This method is reached through the sysext socket, but a single
         * notification refreshes both image classes, so freshly downloaded sysexts and confexts are both
         * picked up, equivalent to "systemd-confext refresh" plus "systemd-sysext refresh", in the same order
         * as at boot. We attempt both classes and only fail afterwards, so a problem with one does not
         * prevent refreshing the other. */

        r = 0;
        RET_GATHER(r, refresh_class(IMAGE_CONFEXT));
        RET_GATHER(r, refresh_class(IMAGE_SYSEXT));
        if (r < 0)
                return r;

        return sd_varlink_reply(link, /* parameters= */ NULL);
}

VERB_NOARG(verb_list, "list", "List installed extensions");
static int verb_list(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_hashmap_free_ Hashmap *images = NULL;
        _cleanup_(table_unrefp) Table *t = NULL;
        Image *img;
        int r;

        r = image_discover(RUNTIME_SCOPE_SYSTEM, arg_image_class, arg_root, &images);
        if (r < 0)
                return log_error_errno(r, "Failed to discover images: %m");

        if (hashmap_isempty(images) && !sd_json_format_enabled(arg_json_format_flags)) {
                log_info("No OS extensions found.");
                return 0;
        }

        t = table_new("name", "type", "path", "time");
        if (!t)
                return log_oom();

        HASHMAP_FOREACH(img, images) {
                r = table_add_many(
                                t,
                                TABLE_STRING, img->name,
                                TABLE_STRING, image_type_to_string(img->type),
                                TABLE_PATH, img->path,
                                TABLE_TIMESTAMP, img->mtime != 0 ? img->mtime : img->crtime);
                if (r < 0)
                        return table_log_add_error(r);
        }

        (void) table_set_sort(t, (size_t) 0);

        return table_print_with_pager(t, arg_json_format_flags, arg_pager_flags, arg_legend);
}

static int vl_method_list(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {

        static const sd_json_dispatch_field dispatch_table[] = {
                { "class", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, 0, 0 },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };
        Hashmap **polkit_registry = ASSERT_PTR(userdata);
        int r;

        assert(link);
        assert(FLAGS_SET(flags, SD_VARLINK_METHOD_MORE));

        const char *class = NULL;
        r = sd_varlink_dispatch(link, parameters, dispatch_table, &class);
        if (r != 0)
                return r;

        ImageClass image_class = arg_image_class;
        r = parse_image_class_parameter(link, class, &image_class);
        if (r < 0)
                return r;

        r = varlink_verify_polkit_async(
                        link,
                        /* bus= */ NULL,
                        image_class_info[image_class].polkit_ro_action_id,
                        (const char**) STRV_MAKE("verb", "list"),
                        polkit_registry);
        if (r <= 0)
                return r;

        _cleanup_hashmap_free_ Hashmap *images = NULL;
        r = image_discover(RUNTIME_SCOPE_SYSTEM, image_class, arg_root, &images);
        if (r < 0)
                return r;

        r = sd_varlink_set_sentinel(link, "io.systemd.sysext.NoImagesFound");
        if (r < 0)
                return r;

        Image *img;
        HASHMAP_FOREACH(img, images) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
                r = image_to_json(img, &v);
                if (r < 0)
                        return r;

                r = sd_varlink_reply(link, v);
                if (r < 0)
                        return r;
        }

        return 0;
}

VERB_FULL(verb_help, "help", NULL, VERB_ANY, VERB_ANY, 0, /* dat= */ 0u, /* help= */ NULL);
static int verb_help(int argc, char **argv, uintptr_t data, void *userdata) {
        return command_print_help_name(
                        arg_image_class == IMAGE_SYSEXT ? "systemd-sysext" : "systemd-confext");
}

static int parse_argv(int argc, char *argv[], char ***ret_args) {
        int r;

        assert(argc >= 0);
        assert(argv);
        assert(ret_args);

        OptionParser opts = { argc, argv };

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_COMMON_HELP:
                        return verb_help(argc, argv, /* data= */ 0u, /* userdata= */ NULL);

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_LONG("root", "PATH", "Operate relative to root PATH"):
                        r = parse_path_argument(opts.arg, /* suppress_root= */ false, &arg_root);
                        if (r < 0)
                                return r;
                        /* If --root= is provided, do not reload the service manager */
                        arg_no_reload = true;
                        break;

                OPTION_LONG("mutable", "MODE",
                            "Specify a mutability mode (yes, no, auto, import, ephemeral, ephemeral-import, help)"):
                        if (streq(opts.arg, "help")) {
                                if (arg_legend)
                                        puts("Known mutability modes:");

                                return DUMP_STRING_TABLE(mutable_mode, MutableMode, _MUTABLE_MAX);
                        }

                        r = parse_mutable_mode(opts.arg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse argument to --mutable=: %s", opts.arg);
                        arg_mutable = r;
                        arg_mutable_argv_set = true;
                        break;

                OPTION_LONG("image-policy", "POLICY", "Specify disk image dissection policy"):
                        r = parse_image_policy_argument(opts.arg, &arg_image_policy);
                        if (r < 0)
                                return r;
                        arg_image_policy_argv_set = true;
                        break;

                OPTION_LONG("noexec", "BOOL", "Whether to mount extension overlay with noexec"):
                        r = parse_boolean_argument("--noexec", opts.arg, /* ret= */ NULL);
                        if (r < 0)
                                return r;

                        arg_noexec = r;
                        break;

                OPTION_LONG("force", NULL, "Ignore version incompatibilities"):
                        arg_force = true;
                        break;

                OPTION_LONG("no-reload", NULL, "Do not reload the service manager"):
                        arg_no_reload = true;
                        break;

                OPTION_LONG("always-refresh", "BOOL", "Whether to refresh when no changes were found"):
                        r = parse_boolean_argument("--always-refresh", opts.arg, &arg_always_refresh);
                        if (r < 0)
                                return r;
                        break;

                OPTION_COMMON_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                OPTION_COMMON_NO_LEGEND:
                        arg_legend = false;
                        break;

                OPTION_COMMON_JSON:
                        r = parse_json_argument(opts.arg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;
                        break;

                OPTION_COMMON_INTROSPECT_CLI:
                        return introspect_cli(arg_json_format_flags);
                }

        if (arg_root) {
                _cleanup_free_ char *resolved_root = NULL;

                /* Resolve the root once, so that paths derived from it contain no symlinks */
                r = chase(arg_root, /* root= */ NULL, CHASE_MUST_BE_DIRECTORY, &resolved_root, /* ret_fd= */ NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to resolve --root='%s': %m", arg_root);

                free_and_replace(arg_root, resolved_root);
        }

        r = sd_varlink_invocation(SD_VARLINK_ALLOW_ACCEPT);
        if (r < 0)
                return log_error_errno(r, "Failed to check if invoked in Varlink mode: %m");
        if (r > 0)
                arg_varlink = true;

        *ret_args = option_parser_get_args(&opts);
        return 1;
}

static int run(int argc, char *argv[]) {
        char **args = NULL;
        int r;

        LIBBLKID_NOTE(required);
        LIBCRYPTO_NOTE(suggested);
        LIBCRYPTSETUP_NOTE(recommended);
        LIBMOUNT_NOTE(required);
        LIBSELINUX_NOTE(recommended);
        TPM2_NOTE(suggested);

        log_setup();

        arg_image_class = invoked_as(argv, "systemd-confext") ? IMAGE_CONFEXT : IMAGE_SYSEXT;

        /* Parse command line */
        r = parse_argv(argc, argv, &args);
        if (r <= 0)
                return r;

        /* PROC_CMDLINE_STRIP_RD_PREFIX cannot be used here as we need to be able to distinguish between
         * rd.systemd.{sysext,confext} and systemd.{sysext,confext} in the initrd where they are both used
         * and have different meaning. */
        const char *string_class = image_class_to_string(arg_image_class);
        const char *cmdline_opt = strjoina(in_initrd() && !arg_root ? "rd." : "", "systemd.", string_class);

        bool enabled;
        r = proc_cmdline_get_bool(cmdline_opt, PROC_CMDLINE_TRUE_WHEN_MISSING, &enabled);
        if (r < 0)
                log_debug_errno(r, "Failed to check '%s=' kernel command line option, proceeding: %m", cmdline_opt);
        else if (!enabled && invoked_by_systemd()) {
                /* Kernel command line option should not affect manual invocation. */
                log_notice("Disabled by the kernel command line option '%s=', skipping execution.", cmdline_opt);
                return 0;
        }

        if (arg_varlink) {
                _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *varlink_server = NULL;
                _cleanup_hashmap_free_ Hashmap *polkit_registry = NULL;

                /* Invocation as Varlink service */

                r = varlink_server_new(
                                &varlink_server,
                                SD_VARLINK_SERVER_ACCOUNT_UID|SD_VARLINK_SERVER_INHERIT_USERDATA,
                                &polkit_registry);
                if (r < 0)
                        return log_error_errno(r, "Failed to allocate Varlink server: %m");

                r = sd_varlink_server_add_interface_many(
                                varlink_server,
                                &vl_interface_io_systemd_sysext,
                                &vl_interface_io_systemd_SysUpdate_Notify);
                if (r < 0)
                        return log_error_errno(r, "Failed to add Varlink interfaces: %m");

                r = sd_varlink_server_bind_method_many(
                                varlink_server,
                                "io.systemd.sysext.Merge", vl_method_merge,
                                "io.systemd.sysext.Unmerge", vl_method_unmerge,
                                "io.systemd.sysext.Refresh", vl_method_refresh,
                                "io.systemd.sysext.List", vl_method_list,
                                "io.systemd.SysUpdate.Notify.OnCompletedUpdate", vl_method_on_completed_update);
                if (r < 0)
                        return log_error_errno(r, "Failed to bind Varlink methods: %m");

                r = sd_varlink_server_loop_auto(varlink_server);
                if (r == -EPERM)
                        return log_error_errno(r, "Invoked by unprivileged Varlink peer, refusing.");
                if (r < 0)
                        return log_error_errno(r, "Failed to run Varlink event loop: %m");

                return EXIT_SUCCESS;
        }

        return dispatch_verb(args, NULL);
}

DEFINE_MAIN_FUNCTION(run);
