/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#include "alloc-util.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-unit-util.h"
#include "chase.h"
#include "creds-util.h"
#include "efi-loader.h"
#include "env-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fstab-util.h"
#include "generator.h"
#include "in-addr-util.h"
#include "initrd-util.h"
#include "log.h"
#include "main-func.h"
#include "mkdir.h"
#include "mount-setup.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "nulstr-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "proc-cmdline.h"
#include "process-util.h"
#include "special.h"
#include "specifier.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "unit-name.h"
#include "virt.h"
#include "volatile-util.h"

typedef enum MountPointFlags {
        MOUNT_NOAUTO    = 1 << 0,
        MOUNT_NOFAIL    = 1 << 1,
        MOUNT_AUTOMOUNT = 1 << 2,
        MOUNT_MAKEFS    = 1 << 3,
        MOUNT_GROWFS    = 1 << 4,
        MOUNT_RW_ONLY   = 1 << 5,
        MOUNT_PCRFS     = 1 << 6,
} MountPointFlags;

typedef struct Mount {
        bool for_initrd;
        char *what;
        char *where;
        char *fstype;
        char *options;
} Mount;

static void mount_array_free(Mount *mounts, size_t n);

static bool arg_sysroot_check = false;
static const char *arg_dest = NULL;
static const char *arg_dest_late = NULL;
static bool arg_fstab_enabled = true;
static bool arg_swap_enabled = true;
static char *arg_root_what = NULL;
static char *arg_root_fstype = NULL;
static char *arg_root_options = NULL;
static char *arg_root_hash = NULL;
static int arg_root_rw = -1;
static char *arg_usr_what = NULL;
static char *arg_usr_fstype = NULL;
static char *arg_usr_options = NULL;
static char *arg_usr_hash = NULL;
static VolatileMode arg_volatile_mode = _VOLATILE_MODE_INVALID;
static bool arg_verity = true;
static Mount *arg_mounts = NULL;
static size_t arg_n_mounts = 0;

STATIC_DESTRUCTOR_REGISTER(arg_root_what, freep);
STATIC_DESTRUCTOR_REGISTER(arg_root_fstype, freep);
STATIC_DESTRUCTOR_REGISTER(arg_root_options, freep);
STATIC_DESTRUCTOR_REGISTER(arg_root_hash, freep);
STATIC_DESTRUCTOR_REGISTER(arg_usr_what, freep);
STATIC_DESTRUCTOR_REGISTER(arg_usr_fstype, freep);
STATIC_DESTRUCTOR_REGISTER(arg_usr_options, freep);
STATIC_DESTRUCTOR_REGISTER(arg_usr_hash, freep);
STATIC_ARRAY_DESTRUCTOR_REGISTER(arg_mounts, arg_n_mounts, mount_array_free);

static void mount_done(Mount *m) {
        assert(m);

        free(m->what);
        free(m->where);
        free(m->fstype);
        free(m->options);
}

static void mount_array_free(Mount *mounts, size_t n) {
        FOREACH_ARRAY(m, mounts, n)
                mount_done(m);

        free(mounts);
}

static int mount_array_add_internal(
                bool for_initrd,
                char *in_what,
                char *in_where,
                const char *in_fstype,
                const char *in_options) {

        _cleanup_free_ char *what = NULL, *where = NULL, *fstype = NULL, *options = NULL;
        int r;

        /* This takes what and where. */

        what = ASSERT_PTR(in_what);
        where = in_where;

        fstype = strdup(isempty(in_fstype) ? "auto" : in_fstype);
        if (!fstype)
                return -ENOMEM;

        if (streq(fstype, "swap"))
                where = mfree(where);

        if (!isempty(in_options)) {
                _cleanup_strv_free_ char **options_strv = NULL;

                r = strv_split_full(&options_strv, in_options, ",", 0);
                if (r < 0)
                        return r;

                r = strv_make_nulstr(options_strv, &options, NULL);
        } else
                r = strv_make_nulstr(STRV_MAKE("defaults"), &options, NULL);
        if (r < 0)
                return r;

        if (!GREEDY_REALLOC(arg_mounts, arg_n_mounts + 1))
                return -ENOMEM;

        arg_mounts[arg_n_mounts++] = (Mount) {
                .for_initrd = for_initrd,
                .what = TAKE_PTR(what),
                .where = TAKE_PTR(where),
                .fstype = TAKE_PTR(fstype),
                .options = TAKE_PTR(options),
        };

        return 0;
}

static int mount_array_add(bool for_initrd, const char *str) {
        _cleanup_free_ char *what = NULL, *where = NULL, *fstype = NULL, *options = NULL;
        int r;

        assert(str);

        r = extract_many_words(&str, ":", EXTRACT_CUNESCAPE | EXTRACT_DONT_COALESCE_SEPARATORS,
                               &what, &where, &fstype, &options, NULL);
        if (r < 0)
                return r;
        if (r < 2)
                return -EINVAL;
        if (!isempty(str))
                return -EINVAL;

        return mount_array_add_internal(for_initrd, TAKE_PTR(what), TAKE_PTR(where), fstype, options);
}

static int mount_array_add_swap(bool for_initrd, const char *str) {
        _cleanup_free_ char *what = NULL, *options = NULL;
        int r;

        assert(str);

        r = extract_many_words(&str, ":", EXTRACT_CUNESCAPE | EXTRACT_DONT_COALESCE_SEPARATORS,
                               &what, &options, NULL);
        if (r < 0)
                return r;
        if (r < 1)
                return -EINVAL;
        if (!isempty(str))
                return -EINVAL;

        return mount_array_add_internal(for_initrd, TAKE_PTR(what), NULL, "swap", options);
}

static int write_options(FILE *f, const char *options) {
        _cleanup_free_ char *o = NULL;

        if (isempty(options))
                return 0;

        if (streq(options, "defaults"))
                return 0;

        o = specifier_escape(options);
        if (!o)
                return log_oom();

        fprintf(f, "Options=%s\n", o);
        return 1;
}

static int write_what(FILE *f, const char *what) {
        _cleanup_free_ char *w = NULL;

        w = specifier_escape(what);
        if (!w)
                return log_oom();

        fprintf(f, "What=%s\n", w);
        return 1;
}

static int add_swap(
                const char *source,
                const char *what,
                const char *options,
                MountPointFlags flags) {

        _cleanup_free_ char *name = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(what);

        if (access("/proc/swaps", F_OK) < 0) {
                log_info("Swap not supported, ignoring swap entry for %s.", what);
                return 0;
        }

        if (detect_container() > 0) {
                log_info("Running in a container, ignoring swap entry for %s.", what);
                return 0;
        }

        if (arg_sysroot_check) {
                log_info("%s should be enabled in the initrd, will request daemon-reload.", what);
                return true;
        }

        log_debug("Found swap entry what=%s makefs=%s growfs=%s pcrfs=%s noauto=%s nofail=%s",
                  what,
                  yes_no(flags & MOUNT_MAKEFS), yes_no(flags & MOUNT_GROWFS), yes_no(flags & MOUNT_PCRFS),
                  yes_no(flags & MOUNT_NOAUTO), yes_no(flags & MOUNT_NOFAIL));

        r = unit_name_from_path(what, ".swap", &name);
        if (r < 0)
                return log_error_errno(r, "Failed to generate unit name: %m");

        r = generator_open_unit_file(arg_dest, source, name, &f);
        if (r < 0)
                return r;

        fprintf(f,
                "[Unit]\n"
                "Documentation=man:fstab(5) man:systemd-fstab-generator(8)\n"
                "SourcePath=%s\n",
                source);

        r = generator_write_blockdev_dependency(f, what);
        if (r < 0)
                return r;

        fprintf(f,
                "\n"
                "[Swap]\n");

        r = write_what(f, what);
        if (r < 0)
                return r;

        r = write_options(f, options);
        if (r < 0)
                return r;

        r = fflush_and_check(f);
        if (r < 0)
                return log_error_errno(r, "Failed to write unit file %s: %m", name);

        /* use what as where, to have a nicer error message */
        r = generator_write_timeouts(arg_dest, what, what, options, NULL);
        if (r < 0)
                return r;

        if (flags & MOUNT_MAKEFS) {
                r = generator_hook_up_mkswap(arg_dest, what);
                if (r < 0)
                        return r;
        }

        if (flags & MOUNT_GROWFS)
                /* TODO: swap devices must be wiped and recreated */
                log_warning("%s: growing swap devices is currently unsupported.", what);
        if (flags & MOUNT_PCRFS)
                log_warning("%s: measuring swap devices is currently unsupported.", what);

        if (!(flags & MOUNT_NOAUTO)) {
                r = generator_add_symlink(arg_dest, SPECIAL_SWAP_TARGET,
                                          (flags & MOUNT_NOFAIL) ? "wants" : "requires", name);
                if (r < 0)
                        return r;
        }

        return true;
}

static bool mount_is_network(const char *fstype, const char *options) {
        return fstab_test_option(options, "_netdev\0") ||
                (fstype && fstype_is_network(fstype));
}

static bool mount_in_initrd(const char *where, const char *options, bool accept_root) {
        return fstab_test_option(options, "x-initrd.mount\0") ||
                (where && PATH_IN_SET(where, "/usr", accept_root ? "/" : NULL));
}

static int write_timeout(
                FILE *f,
                const char *where,
                const char *opts,
                const char *filter,
                const char *variable) {

        _cleanup_free_ char *timeout = NULL;
        usec_t u;
        int r;

        r = fstab_filter_options(opts, filter, NULL, &timeout, NULL, NULL);
        if (r < 0)
                return log_warning_errno(r, "Failed to parse options: %m");
        if (r == 0)
                return 0;

        r = parse_sec_fix_0(timeout, &u);
        if (r < 0) {
                log_warning("Failed to parse timeout for %s, ignoring: %s", where, timeout);
                return 0;
        }

        fprintf(f, "%s=%s\n", variable, FORMAT_TIMESPAN(u, 0));

        return 0;
}

static int write_idle_timeout(FILE *f, const char *where, const char *opts) {
        return write_timeout(f, where, opts,
                             "x-systemd.idle-timeout\0", "TimeoutIdleSec");
}

static int write_mount_timeout(FILE *f, const char *where, const char *opts) {
        return write_timeout(f, where, opts,
                             "x-systemd.mount-timeout\0", "TimeoutSec");
}

static int write_dependency(
                FILE *f,
                const char *opts,
                const char *filter,
                const char *format) {

        _cleanup_strv_free_ char **names = NULL, **units = NULL;
        _cleanup_free_ char *res = NULL;
        int r;

        assert(f);
        assert(opts);

        r = fstab_filter_options(opts, filter, NULL, NULL, &names, NULL);
        if (r < 0)
                return log_warning_errno(r, "Failed to parse options: %m");
        if (r == 0)
                return 0;

        STRV_FOREACH(s, names) {
                char *x;

                r = unit_name_mangle_with_suffix(*s, "as dependency", 0, ".mount", &x);
                if (r < 0)
                        return log_error_errno(r, "Failed to generate unit name: %m");

                r = strv_consume(&units, x);
                if (r < 0)
                        return log_oom();
        }

        if (units) {
                res = strv_join(units, " ");
                if (!res)
                        return log_oom();

                DISABLE_WARNING_FORMAT_NONLITERAL;
                fprintf(f, format, res);
                REENABLE_WARNING;
        }

        return 0;
}

static int write_after(FILE *f, const char *opts) {
        return write_dependency(f, opts,
                                "x-systemd.after\0", "After=%1$s\n");
}

static int write_requires_after(FILE *f, const char *opts) {
        return write_dependency(f, opts,
                                "x-systemd.requires\0", "After=%1$s\nRequires=%1$s\n");
}

static int write_before(FILE *f, const char *opts) {
        return write_dependency(f, opts,
                                "x-systemd.before\0", "Before=%1$s\n");
}

static int write_mounts_for(const char *x_opt, const char *unit_setting, FILE *f, const char *opts) {
        _cleanup_strv_free_ char **paths = NULL, **paths_escaped = NULL;
        _cleanup_free_ char *res = NULL;
        int r;

        assert(x_opt);
        assert(unit_setting);
        assert(f);
        assert(opts);

        r = fstab_filter_options(opts, x_opt, NULL, NULL, &paths, NULL);
        if (r < 0)
                return log_warning_errno(r, "Failed to parse options: %m");
        if (r == 0)
                return 0;

        r = specifier_escape_strv(paths, &paths_escaped);
        if (r < 0)
                return log_error_errno(r, "Failed to escape paths: %m");

        res = strv_join(paths_escaped, " ");
        if (!res)
                return log_oom();

        fprintf(f, "%s=%s\n", unit_setting, res);

        return 0;
}

static int write_extra_dependencies(FILE *f, const char *opts) {
        int r;

        assert(f);

        if (opts) {
                r = write_after(f, opts);
                if (r < 0)
                        return r;
                r = write_requires_after(f, opts);
                if (r < 0)
                        return r;
                r = write_before(f, opts);
                if (r < 0)
                        return r;
                r = write_mounts_for("x-systemd.requires-mounts-for\0", "RequiresMountsFor", f, opts);
                if (r < 0)
                        return r;
                r = write_mounts_for("x-systemd.wants-mounts-for\0", "WantsMountsFor", f, opts);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int mandatory_mount_drop_unapplicable_options(
                MountPointFlags *flags,
                const char *where,
                const char *options,
                char **ret_options) {

        int r;

        assert(flags);
        assert(where);
        assert(options);
        assert(ret_options);

        if (!(*flags & (MOUNT_NOAUTO|MOUNT_NOFAIL|MOUNT_AUTOMOUNT))) {
                _cleanup_free_ char *opts = NULL;

                opts = strdup(options);
                if (!opts)
                        return -ENOMEM;

                *ret_options = TAKE_PTR(opts);
                return 0;
        }

        log_debug("Mount '%s' is mandatory, ignoring 'noauto', 'nofail', and 'x-systemd.automount' options.",
                  where);

        *flags &= ~(MOUNT_NOAUTO|MOUNT_NOFAIL|MOUNT_AUTOMOUNT);

        r = fstab_filter_options(options, "noauto\0nofail\0x-systemd.automount\0", NULL, NULL, NULL, ret_options);
        if (r < 0)
                return r;

        return 1;
}

static int add_mount(
                const char *source,
                const char *dest,
                const char *what,
                const char *where,
                const char *original_where,
                const char *fstype,
                const char *opts,
                int passno,
                MountPointFlags flags,
                const char *target_unit) {

        _cleanup_free_ char *name = NULL, *automount_name = NULL, *filtered = NULL, *where_escaped = NULL,
                *opts_root_filtered = NULL;
        _cleanup_strv_free_ char **wanted_by = NULL, **required_by = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(what);
        assert(where);
        assert(opts);
        assert(target_unit);
        assert(source);

        if (streq_ptr(fstype, "autofs"))
                return 0;

        if (!is_path(where)) {
                log_warning("Mount point %s is not a valid path, ignoring.", where);
                return 0;
        }

        if (mount_point_is_api(where) ||
            mount_point_ignore(where))
                return 0;

        if (arg_sysroot_check) {
                log_info("%s should be mounted in the initrd, will request daemon-reload.", where);
                return true;
        }

        r = fstab_filter_options(opts, "x-systemd.wanted-by\0", NULL, NULL, &wanted_by, NULL);
        if (r < 0)
                return r;

        r = fstab_filter_options(opts, "x-systemd.required-by\0", NULL, NULL, &required_by, NULL);
        if (r < 0)
                return r;

        if (path_equal(where, "/")) {
                r = mandatory_mount_drop_unapplicable_options(&flags, where, opts, &opts_root_filtered);
                if (r < 0)
                        return r;
                opts = opts_root_filtered;

                if (!strv_isempty(wanted_by))
                        log_debug("Ignoring 'x-systemd.wanted-by=' option for root device.");
                if (!strv_isempty(required_by))
                        log_debug("Ignoring 'x-systemd.required-by=' option for root device.");

                required_by = strv_free(required_by);
                wanted_by = strv_free(wanted_by);
        }

        r = unit_name_from_path(where, ".mount", &name);
        if (r < 0)
                return log_error_errno(r, "Failed to generate unit name: %m");

        r = generator_open_unit_file(dest, source, name, &f);
        if (r < 0)
                return r;

        fprintf(f,
                "[Unit]\n"
                "Documentation=man:fstab(5) man:systemd-fstab-generator(8)\n"
                "SourcePath=%s\n",
                source);

        if (STRPTR_IN_SET(fstype, "nfs", "nfs4") && !(flags & MOUNT_AUTOMOUNT) &&
            fstab_test_yes_no_option(opts, "bg\0" "fg\0")) {
                /* The default retry timeout that mount.nfs uses for 'bg' mounts
                 * is 10000 minutes, where as it uses 2 minutes for 'fg' mounts.
                 * As we are making  'bg' mounts look like an 'fg' mount to
                 * mount.nfs (so systemd can manage the job-control aspects of 'bg'),
                 * we need to explicitly preserve that default, and also ensure
                 * the systemd mount-timeout doesn't interfere.
                 * By placing these options first, they can be overridden by
                 * settings in /etc/fstab. */
                opts = strjoina("x-systemd.mount-timeout=infinity,retry=10000,nofail,", opts, ",fg");
                SET_FLAG(flags, MOUNT_NOFAIL, true);
        }

        r = write_extra_dependencies(f, opts);
        if (r < 0)
                return r;

        /* Order the mount unit we generate relative to target_unit, so that DefaultDependencies= on the
         * target unit won't affect us. */
        if (!FLAGS_SET(flags, MOUNT_NOFAIL))
                fprintf(f, "Before=%s\n", target_unit);

        if (passno != 0) {
                r = generator_write_fsck_deps(f, dest, what, where, fstype);
                if (r < 0)
                        return r;
        }

        r = generator_write_blockdev_dependency(f, what);
        if (r < 0)
                return r;

        fprintf(f,
                "\n"
                "[Mount]\n");

        r = write_what(f, what);
        if (r < 0)
                return r;

        if (original_where)
                fprintf(f, "# Canonicalized from %s\n", original_where);

        where_escaped = specifier_escape(where);
        if (!where_escaped)
                return log_oom();
        fprintf(f, "Where=%s\n", where_escaped);

        if (!isempty(fstype) && !streq(fstype, "auto")) {
                _cleanup_free_ char *t = NULL;

                t = specifier_escape(fstype);
                if (!t)
                        return -ENOMEM;

                fprintf(f, "Type=%s\n", t);
        }

        r = generator_write_timeouts(dest, what, where, opts, &filtered);
        if (r < 0)
                return r;

        r = generator_write_device_deps(dest, what, where, opts);
        if (r < 0)
                return r;

        if (in_initrd() && path_equal(where, "/sysroot") && is_device_path(what)) {
                r = generator_write_initrd_root_device_deps(dest, what);
                if (r < 0)
                        return r;
        }

        r = write_mount_timeout(f, where, opts);
        if (r < 0)
                return r;

        r = write_options(f, filtered);
        if (r < 0)
                return r;

        if (flags & MOUNT_RW_ONLY)
                fprintf(f, "ReadWriteOnly=yes\n");

        r = fflush_and_check(f);
        if (r < 0)
                return log_error_errno(r, "Failed to write unit file %s: %m", name);

        if (flags & MOUNT_MAKEFS) {
                r = generator_hook_up_mkfs(dest, what, where, fstype);
                if (r < 0)
                        return r;
        }

        if (flags & MOUNT_GROWFS) {
                r = generator_hook_up_growfs(dest, where, target_unit);
                if (r < 0)
                        return r;
        }

        if (flags & MOUNT_PCRFS) {
                r = efi_measured_uki(LOG_WARNING);
                if (r == 0)
                        log_debug("Kernel stub did not measure kernel image into PCR, skipping userspace measurement, too.");
                else if (r > 0) {
                        r = generator_hook_up_pcrfs(dest, where, target_unit);
                        if (r < 0)
                                return r;
                }
        }

        if (!FLAGS_SET(flags, MOUNT_AUTOMOUNT)) {
                if (!FLAGS_SET(flags, MOUNT_NOAUTO) && strv_isempty(wanted_by) && strv_isempty(required_by)) {
                        r = generator_add_symlink(dest, target_unit,
                                                  (flags & MOUNT_NOFAIL) ? "wants" : "requires", name);
                        if (r < 0)
                                return r;
                } else {
                        STRV_FOREACH(s, wanted_by) {
                                r = generator_add_symlink(dest, *s, "wants", name);
                                if (r < 0)
                                        return r;
                        }

                        STRV_FOREACH(s, required_by) {
                                r = generator_add_symlink(dest, *s, "requires", name);
                                if (r < 0)
                                        return r;
                        }
                }
        } else {
                r = unit_name_from_path(where, ".automount", &automount_name);
                if (r < 0)
                        return log_error_errno(r, "Failed to generate unit name: %m");

                f = safe_fclose(f);

                r = generator_open_unit_file(dest, source, automount_name, &f);
                if (r < 0)
                        return r;

                fprintf(f,
                        "[Unit]\n"
                        "SourcePath=%s\n"
                        "Documentation=man:fstab(5) man:systemd-fstab-generator(8)\n",
                        source);

                fprintf(f,
                        "\n"
                        "[Automount]\n"
                        "Where=%s\n",
                        where_escaped);

                r = write_idle_timeout(f, where, opts);
                if (r < 0)
                        return r;

                r = fflush_and_check(f);
                if (r < 0)
                        return log_error_errno(r, "Failed to write unit file %s: %m", automount_name);

                r = generator_add_symlink(dest, target_unit,
                                          (flags & MOUNT_NOFAIL) ? "wants" : "requires", automount_name);
                if (r < 0)
                        return r;
        }

        return true;
}

static int do_daemon_reload(void) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r, k;

        log_debug("Calling org.freedesktop.systemd1.Manager.Reload()...");

        r = bus_connect_system_systemd(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to get D-Bus connection: %m");

        r = bus_service_manager_reload(bus);
        if (r < 0)
                return r;

        /* We need to requeue the two targets so that any new units which previously were not part of the
         * targets, and which we now added, will be started. */

        r = 0;
        FOREACH_STRING(unit, SPECIAL_INITRD_FS_TARGET, SPECIAL_SWAP_TARGET) {
                log_info("Requesting %s/start/replace...", unit);

                k = bus_call_method(bus, bus_systemd_mgr, "StartUnit", &error, NULL, "ss", unit, "replace");
                if (k < 0) {
                        log_error_errno(k, "Failed to (re)start %s: %s", unit, bus_error_message(&error, r));
                        RET_GATHER(r, k);
                }
        }

        return r;
}

static const char* sysroot_fstab_path(void) {
        return getenv("SYSTEMD_SYSROOT_FSTAB") ?: "/sysroot/etc/fstab";
}

static bool sysfs_check(void) {
        static int cached = -1;
        int r;

        if (cached < 0) {
                r = getenv_bool_secure("SYSTEMD_SYSFS_CHECK");
                if (r < 0 && r != -ENXIO)
                        log_debug_errno(r, "Failed to parse $SYSTEMD_SYSFS_CHECK, ignoring: %m");
                cached = r != 0;
        }

        return cached;
}

static int add_sysusr_sysroot_usr_bind_mount(const char *source) {
        return add_mount(source,
                        arg_dest,
                        "/sysusr/usr",
                        "/sysroot/usr",
                        NULL,
                        NULL,
                        "bind",
                        0,
                        0,
                        SPECIAL_INITRD_FS_TARGET);
}

static MountPointFlags fstab_options_to_flags(const char *options, bool is_swap) {
        MountPointFlags flags = 0;

        if (fstab_test_option(options, "x-systemd.makefs\0"))
                flags |= MOUNT_MAKEFS;
        if (fstab_test_option(options, "x-systemd.growfs\0"))
                flags |= MOUNT_GROWFS;
        if (fstab_test_option(options, "x-systemd.pcrfs\0"))
                flags |= MOUNT_PCRFS;
        if (fstab_test_yes_no_option(options, "noauto\0" "auto\0"))
                flags |= MOUNT_NOAUTO;
        if (fstab_test_yes_no_option(options, "nofail\0" "fail\0"))
                flags |= MOUNT_NOFAIL;

        if (!is_swap) {
                if (fstab_test_option(options, "x-systemd.rw-only\0"))
                        flags |= MOUNT_RW_ONLY;
                if (fstab_test_option(options,
                                      "comment=systemd.automount\0"
                                      "x-systemd.automount\0"))
                        flags |= MOUNT_AUTOMOUNT;
        }

        return flags;
}

static int canonicalize_mount_path(const char *path, const char *type, bool prefix_sysroot, char **ret) {
        _cleanup_free_ char *p = NULL;
        bool changed;
        int r;

        assert(path);
        assert(type);
        assert(STR_IN_SET(type, "where", "what"));
        assert(ret);

        // FIXME: when chase() learns to chase non-existent paths, use this here and drop the prefixing with
        // /sysroot on error below.
        r = chase(path, prefix_sysroot ? "/sysroot" : NULL, CHASE_PREFIX_ROOT | CHASE_NONEXISTENT, &p, NULL);
        if (r < 0) {
                log_debug_errno(r, "Failed to chase '%s', using as-is: %m", path);

                if (prefix_sysroot)
                        p = path_join("/sysroot", path);
                else
                        p = strdup(path);
                if (!p)
                        return log_oom();

                path_simplify(p);
        }

        changed = !streq(path, p);
        if (changed)
                log_debug("Canonicalized %s=%s to %s", type, path, p);

        *ret = TAKE_PTR(p);
        return changed;
}

static int parse_fstab_one(
                const char *source,
                const char *what_original,
                const char *where_original,
                const char *fstype,
                const char *options,
                int passno,
                bool prefix_sysroot,
                bool accept_root, /* This takes an effect only when prefix_sysroot is true. */
                bool use_swap_enabled) {

        _cleanup_free_ char *what = NULL, *where = NULL, *opts = NULL;
        MountPointFlags flags;
        bool is_swap, where_changed;
        int r;

        assert(what_original);
        assert(fstype);
        assert(options);

        if (prefix_sysroot && !mount_in_initrd(where_original, options, accept_root))
                return 0;

        is_swap = streq_ptr(fstype, "swap");
        if (is_swap && use_swap_enabled && !arg_swap_enabled) {
                log_info("Swap unit generation disabled on kernel command line, ignoring swap entry for %s.", what_original);
                return 0;
        }

        what = fstab_node_to_udev_node(what_original);
        if (!what)
                return log_oom();

        if (path_is_read_only_fs("/sys") > 0 &&
            (streq(what, "sysfs") ||
             (sysfs_check() && is_device_path(what)))) {
                log_info("/sys/ is read-only (running in a container?), ignoring mount for %s.", what);
                return 0;
        }

        flags = fstab_options_to_flags(options, is_swap);

        if (is_swap)
                return add_swap(source, what, options, flags);

        if (passno < 0)
                passno = is_device_path(what);

        assert(where_original); /* 'where' is not necessary for swap entry. */

        if (!is_path(where_original)) {
                log_warning("Mount point %s is not a valid path, ignoring.", where_original);
                return 0;
        }

        /* Follow symlinks here; see 5261ba901845c084de5a8fd06500ed09bfb0bd80 which makes sense for
         * mount units, but causes problems since it historically worked to have symlinks in e.g.
         * /etc/fstab. So we canonicalize here. Note that we use CHASE_NONEXISTENT to handle the case
         * where a symlink refers to another mount target; this works assuming the sub-mountpoint
         * target is the final directory. */
        r = canonicalize_mount_path(where_original, "where", prefix_sysroot, &where);
        if (r < 0)
                return r;
        where_changed = r > 0;

        if (prefix_sysroot && fstab_is_bind(options, fstype)) {
                /* When in initrd, the source of bind mount needs to be prepended with /sysroot as well. */
                _cleanup_free_ char *p = NULL;

                r = canonicalize_mount_path(what, "what", prefix_sysroot, &p);
                if (r < 0)
                        return r;

                free_and_replace(what, p);
        }

        log_debug("Found entry what=%s where=%s type=%s makefs=%s growfs=%s pcrfs=%s noauto=%s nofail=%s",
                  what, where, strna(fstype),
                  yes_no(flags & MOUNT_MAKEFS), yes_no(flags & MOUNT_GROWFS), yes_no(flags & MOUNT_PCRFS),
                  yes_no(flags & MOUNT_NOAUTO), yes_no(flags & MOUNT_NOFAIL));

        bool is_sysroot = in_initrd() && path_equal(where, "/sysroot");
        /* See comment from add_sysroot_usr_mount() about the need for extra indirection in case /usr needs
         * to be mounted in order for the root fs to be synthesized based on configuration included in /usr/,
         * e.g. systemd-repart. */
        bool is_sysroot_usr = in_initrd() && path_equal(where, "/sysroot/usr");

        const char *target_unit =
                        is_sysroot ?                        SPECIAL_INITRD_ROOT_FS_TARGET :
                        is_sysroot_usr ?                    SPECIAL_INITRD_USR_FS_TARGET :
                        prefix_sysroot ?                    SPECIAL_INITRD_FS_TARGET :
                        mount_is_network(fstype, options) ? SPECIAL_REMOTE_FS_TARGET :
                                                            SPECIAL_LOCAL_FS_TARGET;

        /* nofail, noauto and x-systemd.automount don't make sense for critical filesystems we must mount in initrd. */
        if (is_sysroot || is_sysroot_usr) {
                r = mandatory_mount_drop_unapplicable_options(&flags, where, options, &opts);
                if (r < 0)
                        return r;
                options = opts;
        }

        r = add_mount(source,
                      arg_dest,
                      what,
                      is_sysroot_usr ? "/sysusr/usr" : where,
                      !is_sysroot_usr && where_changed ? where_original : NULL,
                      fstype,
                      options,
                      passno,
                      flags,
                      target_unit);
        if (r <= 0)
                return r;

        if (is_sysroot_usr) {
                log_debug("Synthesizing fstab entry what=/sysusr/usr where=/sysroot/usr opts=bind");
                r = add_sysusr_sysroot_usr_bind_mount(source);
                if (r < 0)
                        return r;
        }

        return true;
}

static int parse_fstab(bool prefix_sysroot) {
        _cleanup_endmntent_ FILE *f = NULL;
        const char *fstab;
        struct mntent *me;
        int r, ret = 0;

        if (prefix_sysroot)
                fstab = sysroot_fstab_path();
        else {
                fstab = fstab_path();
                assert(!arg_sysroot_check);
        }

        log_debug("Parsing %s...", fstab);

        f = setmntent(fstab, "re");
        if (!f) {
                if (errno == ENOENT)
                        return 0;

                return log_error_errno(errno, "Failed to open %s: %m", fstab);
        }

        while ((me = getmntent(f))) {
                r = parse_fstab_one(fstab,
                                    me->mnt_fsname, me->mnt_dir, me->mnt_type, me->mnt_opts, me->mnt_passno,
                                    prefix_sysroot,
                                    /* accept_root = */ false,
                                    /* use_swap_enabled = */ true);
                if (r < 0 && ret >= 0)
                        ret = r;
                if (arg_sysroot_check && r > 0)
                        return true;  /* We found a mount or swap that would be started… */
        }

        return ret;
}

static int sysroot_is_nfsroot(void) {
        union in_addr_union u;
        const char *sep, *a;
        int r;

        assert(arg_root_what);

        /* From dracut.cmdline(7).
         *
         * root=[<server-ip>:]<root-dir>[:<nfs-options>]
         * root=nfs:[<server-ip>:]<root-dir>[:<nfs-options>],
         * root=nfs4:[<server-ip>:]<root-dir>[:<nfs-options>],
         * root={dhcp|dhcp6}
         *
         * mount nfs share from <server-ip>:/<root-dir>, if no server-ip is given, use dhcp next_server.
         * If server-ip is an IPv6 address it has to be put in brackets, e.g. [2001:DB8::1]. NFS options
         * can be appended with the prefix ":" or "," and are separated by ",". */

        if (path_equal(arg_root_what, "/dev/nfs") ||
            STR_IN_SET(arg_root_what, "dhcp", "dhcp6") ||
            STARTSWITH_SET(arg_root_what, "nfs:", "nfs4:"))
                return true;

        /* IPv6 address */
        if (arg_root_what[0] == '[') {
                sep = strchr(arg_root_what + 1, ']');
                if (!sep)
                        return -EINVAL;

                a = strndupa_safe(arg_root_what + 1, sep - arg_root_what - 1);

                r = in_addr_from_string(AF_INET6, a, &u);
                if (r < 0)
                        return r;

                return true;
        }

        /* IPv4 address */
        sep = strchr(arg_root_what, ':');
        if (sep) {
                a = strndupa_safe(arg_root_what, sep - arg_root_what);

                if (in_addr_from_string(AF_INET, a, &u) >= 0)
                        return true;
        }

        /* root directory without address */
        return path_is_absolute(arg_root_what) && !path_startswith(arg_root_what, "/dev");
}

static int add_sysroot_mount(void) {
        _cleanup_free_ char *what = NULL;
        const char *opts, *fstype;
        bool default_rw, makefs;
        MountPointFlags flags;
        int r;

        if (isempty(arg_root_what)) {
                log_debug("Could not find a root= entry on the kernel command line.");
                return 0;
        }

        if (streq(arg_root_what, "gpt-auto")) {
                /* This is handled by gpt-auto-generator */
                log_debug("Skipping root directory handling, as gpt-auto was requested.");
                return 0;
        } else if (streq(arg_root_what, "fstab")) {
                /* This is handled by parse_fstab */
                log_debug("Using initrd's fstab for /sysroot/ configuration.");
                return 0;
        }

        r = sysroot_is_nfsroot();
        if (r < 0)
                log_debug_errno(r, "Failed to determine if the root directory is on NFS, assuming not: %m");
        else if (r > 0) {
                /* This is handled by the kernel or the initrd */
                log_debug("Skipping root directory handling, as root on NFS was requested.");
                return 0;
        }

        if (startswith(arg_root_what, "cifs://")) {
                log_debug("Skipping root directory handling, as root on CIFS was requested.");
                return 0;
        }

        if (startswith(arg_root_what, "iscsi:")) {
                log_debug("Skipping root directory handling, as root on iSCSI was requested.");
                return 0;
        }

        if (startswith(arg_root_what, "live:")) {
                log_debug("Skipping root directory handling, as root on live image was requested.");
                return 0;
        }

        if (streq(arg_root_what, "tmpfs")) {
                /* If root=tmpfs is specified, then take this as shortcut for a writable tmpfs mount as root */

                what = strdup("rootfs"); /* just a pretty name, to show up in /proc/self/mountinfo */
                if (!what)
                        return log_oom();

                fstype = arg_root_fstype ?: "tmpfs"; /* tmpfs, unless overridden */

                default_rw = true; /* writable, unless overridden */;
        } else {

                what = fstab_node_to_udev_node(arg_root_what);
                if (!what)
                        return log_oom();

                fstype = arg_root_fstype; /* if not specified explicitly, don't default to anything here */

                default_rw = false; /* read-only, unless overridden */
        }

        if (!arg_root_options)
                opts = arg_root_rw > 0 || (arg_root_rw < 0 && default_rw) ? "rw" : "ro";
        else if (arg_root_rw >= 0 ||
                 !fstab_test_option(arg_root_options, "ro\0" "rw\0"))
                opts = strjoina(arg_root_options, ",", arg_root_rw > 0 ? "rw" : "ro");
        else
                opts = arg_root_options;

        log_debug("Found entry what=%s where=/sysroot type=%s opts=%s", what, strna(arg_root_fstype), strempty(opts));

        makefs = fstab_test_option(opts, "x-systemd.makefs\0");
        flags = makefs * MOUNT_MAKEFS;

        return add_mount("/proc/cmdline",
                         arg_dest,
                         what,
                         "/sysroot",
                         NULL,
                         fstype,
                         opts,
                         is_device_path(what) ? 1 : 0, /* passno */
                         flags,                        /* makefs off, pcrfs off, noauto off, nofail off, automount off */
                         SPECIAL_INITRD_ROOT_FS_TARGET);
}

static int add_sysroot_usr_mount(void) {
        _cleanup_free_ char *what = NULL;
        const char *opts;
        bool makefs;
        MountPointFlags flags;
        int r;

        /* Returns 0 if we didn't do anything, > 0 if we either generated a unit for the /usr/ mount, or we
         * know for sure something else did */

        if (!arg_usr_what && !arg_usr_fstype && !arg_usr_options)
                return 0;

        if (arg_root_what && !arg_usr_what) {
                /* Copy over the root device, in case the /usr mount just differs in a mount option (consider btrfs subvolumes) */
                arg_usr_what = strdup(arg_root_what);
                if (!arg_usr_what)
                        return log_oom();
        }

        if (arg_root_fstype && !arg_usr_fstype) {
                arg_usr_fstype = strdup(arg_root_fstype);
                if (!arg_usr_fstype)
                        return log_oom();
        }

        if (arg_root_options && !arg_usr_options) {
                arg_usr_options = strdup(arg_root_options);
                if (!arg_usr_options)
                        return log_oom();
        }

        if (isempty(arg_usr_what)) {
                log_debug("Could not find a mount.usr= entry on the kernel command line.");
                return 0;
        }

        if (streq(arg_usr_what, "gpt-auto")) {
                /* This is handled by the gpt-auto generator */
                log_debug("Skipping /usr/ directory handling, as gpt-auto was requested.");
                return 1; /* systemd-gpt-auto-generator will generate a unit for this, hence report that a
                           * unit file is being created for the host /usr/ mount. */
        } else if (streq(arg_usr_what, "fstab")) {
                /* This is handled by parse_fstab */
                log_debug("Using initrd's fstab for /sysroot/usr/ configuration.");
                return 1; /* parse_fstab will generate a unit for this, hence report that a
                           * unit file is being created for the host /usr/ mount. */
        }

        if (path_equal(arg_usr_what, "/dev/nfs")) {
                /* This is handled by the initrd (if at all supported, that is) */
                log_debug("Skipping /usr/ directory handling, as /dev/nfs was requested.");
                return 1; /* As above, report that NFS code will create the unit */
        }

        what = fstab_node_to_udev_node(arg_usr_what);
        if (!what)
                return log_oom();

        if (!arg_usr_options)
                opts = arg_root_rw > 0 ? "rw" : "ro";
        else if (!fstab_test_option(arg_usr_options, "ro\0" "rw\0"))
                opts = strjoina(arg_usr_options, ",", arg_root_rw > 0 ? "rw" : "ro");
        else
                opts = arg_usr_options;

        /* When mounting /usr from the initrd, we add an extra level of indirection: we first mount the /usr/
         * partition to /sysusr/usr/, and then afterwards bind mount that to /sysroot/usr/. We do this so
         * that we can cover for systems that initially only have a /usr/ around and where the root fs needs
         * to be synthesized, based on configuration included in /usr/, e.g. systemd-repart. Software like
         * this should order itself after initrd-usr-fs.target and before initrd-fs.target; and it should
         * look into both /sysusr/ and /sysroot/ for the configuration data to apply. */

        log_debug("Found entry what=%s where=/sysusr/usr type=%s opts=%s", what, strna(arg_usr_fstype), strempty(opts));

        makefs = fstab_test_option(opts, "x-systemd.makefs\0");
        flags = makefs * MOUNT_MAKEFS;

        r = add_mount("/proc/cmdline",
                      arg_dest,
                      what,
                      "/sysusr/usr",
                      NULL,
                      arg_usr_fstype,
                      opts,
                      is_device_path(what) ? 1 : 0, /* passno */
                      flags,
                      SPECIAL_INITRD_USR_FS_TARGET);
        if (r < 0)
                return r;

        log_debug("Synthesizing entry what=/sysusr/usr where=/sysroot/usr opts=bind");

        r = add_sysusr_sysroot_usr_bind_mount("/proc/cmdline");
        if (r < 0)
                return r;

        return 1;
}

static int add_sysroot_usr_mount_or_fallback(void) {
        int r;

        r = add_sysroot_usr_mount();
        if (r != 0)
                return r;

        /* OK, so we didn't write anything out for /sysusr/usr/ nor /sysroot/usr/. In this case, let's make
         * sure that initrd-usr-fs.target is at least ordered after sysroot.mount so that services that order
         * themselves after it get the guarantee that /usr/ is definitely mounted somewhere. */

        return generator_add_symlink(
                        arg_dest,
                        SPECIAL_INITRD_USR_FS_TARGET,
                        "requires",
                        "sysroot.mount");
}

static int add_volatile_root(void) {

        /* Let's add in systemd-remount-volatile.service which will remount the root device to tmpfs if this is
         * requested (or as an overlayfs), leaving only /usr from the root mount inside. */

        if (!IN_SET(arg_volatile_mode, VOLATILE_YES, VOLATILE_OVERLAY))
                return 0;

        return generator_add_symlink(arg_dest, SPECIAL_INITRD_ROOT_FS_TARGET, "requires",
                                     SYSTEM_DATA_UNIT_DIR "/" SPECIAL_VOLATILE_ROOT_SERVICE);
}

static int add_volatile_var(void) {

        if (arg_volatile_mode != VOLATILE_STATE)
                return 0;

        /* If requested, mount /var as tmpfs, but do so only if there's nothing else defined for this. */

        return add_mount("/proc/cmdline",
                         arg_dest_late,
                         "tmpfs",
                         "/var",
                         NULL,
                         "tmpfs",
                         "mode=0755" TMPFS_LIMITS_VAR,
                         0,
                         0,
                         SPECIAL_LOCAL_FS_TARGET);
}

static int add_mounts_from_cmdline(void) {
        int r = 0;

        /* Handle each entries found in cmdline as a fstab entry. */

        FOREACH_ARRAY(m, arg_mounts, arg_n_mounts) {
                if (m->for_initrd && !in_initrd())
                        continue;

                RET_GATHER(r, parse_fstab_one("/proc/cmdline",
                                              m->what,
                                              m->where,
                                              m->fstype,
                                              m->options,
                                              /* passno = */ -1,
                                              /* prefix_sysroot = */ !m->for_initrd && in_initrd(),
                                              /* accept_root = */ true,
                                              /* use_swap_enabled = */ false));
        }

        return r;
}

static int add_mounts_from_creds(bool prefix_sysroot) {
        _cleanup_free_ void *b = NULL;
        struct mntent *me;
        size_t bs;
        int r;

        assert(in_initrd() || !prefix_sysroot);

        r = read_credential_with_decryption(
                        in_initrd() && !prefix_sysroot ? "fstab.extra.initrd" : "fstab.extra",
                        &b, &bs);
        if (r <= 0)
                return r;

        _cleanup_fclose_ FILE *f = NULL;
        f = fmemopen_unlocked(b, bs, "r");
        if (!f)
                return log_oom();

        r = 0;

        while ((me = getmntent(f)))
                RET_GATHER(r, parse_fstab_one("/run/credentials",
                                              me->mnt_fsname,
                                              me->mnt_dir,
                                              me->mnt_type,
                                              me->mnt_opts,
                                              me->mnt_passno,
                                              /* prefix_sysroot = */ prefix_sysroot,
                                              /* accept_root = */ true,
                                              /* use_swap_enabled = */ true));

        return r;
}

static int parse_proc_cmdline_item(const char *key, const char *value, void *data) {
        int r;

        assert(key);

        /* root=, usr=, usrfstype= and roofstype= may occur more than once, the last
         * instance should take precedence.  In the case of multiple rootflags=
         * or usrflags= the arguments should be concatenated */

        if (STR_IN_SET(key, "fstab", "rd.fstab")) {

                r = value ? parse_boolean(value) : 1;
                if (r < 0)
                        log_warning("Failed to parse fstab switch %s. Ignoring.", value);
                else
                        arg_fstab_enabled = fstab_set_enabled(r);

        } else if (streq(key, "root")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                return free_and_strdup_warn(&arg_root_what, empty_to_null(value));

        } else if (streq(key, "rootfstype")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                return free_and_strdup_warn(&arg_root_fstype, empty_to_null(value));

        } else if (streq(key, "rootflags")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                if (!strextend_with_separator(&arg_root_options, ",", value))
                        return log_oom();

        } else if (streq(key, "roothash")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                return free_and_strdup_warn(&arg_root_hash, empty_to_null(value));

        } else if (streq(key, "mount.usr")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                return free_and_strdup_warn(&arg_usr_what, empty_to_null(value));

        } else if (streq(key, "mount.usrfstype")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                return free_and_strdup_warn(&arg_usr_fstype, empty_to_null(value));

        } else if (streq(key, "mount.usrflags")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                if (!strextend_with_separator(&arg_usr_options, ",", value))
                        return log_oom();

        } else if (streq(key, "usrhash")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                return free_and_strdup_warn(&arg_usr_hash, empty_to_null(value));

        } else if (streq(key, "rw") && !value)
                arg_root_rw = true;
        else if (streq(key, "ro") && !value)
                arg_root_rw = false;
        else if (streq(key, "systemd.volatile")) {
                VolatileMode m;

                if (value) {
                        m = volatile_mode_from_string(value);
                        if (m < 0)
                                log_warning_errno(m, "Failed to parse systemd.volatile= argument: %s", value);
                        else
                                arg_volatile_mode = m;
                } else
                        arg_volatile_mode = VOLATILE_YES;

        } else if (streq(key, "systemd.swap")) {

                r = value ? parse_boolean(value) : 1;
                if (r < 0)
                        log_warning("Failed to parse systemd.swap switch %s. Ignoring.", value);
                else
                        arg_swap_enabled = r;

        } else if (streq(key, "systemd.verity")) {

                r = value ? parse_boolean(value) : 1;
                if (r < 0)
                        log_warning("Failed to parse systemd.verity= kernel command line switch %s. Ignoring.", value);
                else
                        arg_verity = r;

        } else if (STR_IN_SET(key, "systemd.mount-extra", "rd.systemd.mount-extra")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = mount_array_add(startswith(key, "rd."), value);
                if (r < 0)
                        log_warning("Failed to parse systemd.mount-extra= option, ignoring: %s", value);

        } else if (STR_IN_SET(key, "systemd.swap-extra", "rd.systemd.swap-extra")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = mount_array_add_swap(startswith(key, "rd."), value);
                if (r < 0)
                        log_warning("Failed to parse systemd.swap-extra= option, ignoring: %s", value);
        }

        return 0;
}

static int determine_device(
                char **what,
                int *rw,
                char **options,
                const char *hash,
                const char *name) {

        assert(what);
        assert(name);

        /* If we have a hash but no device then Verity is used, and we use the DM device. */
        if (*what)
                return 0;

        if (!hash)
                return 0;

        if (!arg_verity)
                return 0;

        *what = path_join("/dev/mapper/", name);
        if (!*what)
                return log_oom();

        /* Verity is always read-only */
        if (rw)
                *rw = false;
        if (options && !strextend_with_separator(options, ",", "ro"))
                return log_oom();

        log_info("Using verity %s device %s.", name, *what);
        return 1;
}

static int determine_root(void) {
        return determine_device(&arg_root_what, &arg_root_rw, NULL, arg_root_hash, "root");
}

static int determine_usr(void) {
        return determine_device(&arg_usr_what, NULL, &arg_usr_options, arg_usr_hash, "usr");
}

/* If arg_sysroot_check is false, run as generator in the usual fashion.
 * If it is true, check /sysroot/etc/fstab for any units that we'd want to mount
 * in the initrd, and call daemon-reload. We will get reinvoked as a generator,
 * with /sysroot/etc/fstab available, and then we can write additional units based
 * on that file. */
static int run_generator(void) {
        int r = 0;

        r = proc_cmdline_parse(parse_proc_cmdline_item, NULL, 0);
        if (r < 0)
                log_warning_errno(r, "Failed to parse kernel command line, ignoring: %m");

        (void) determine_root();
        (void) determine_usr();

        if (arg_sysroot_check) {
                r = parse_fstab(/* prefix_sysroot = */ true);
                if (r == 0)
                        log_debug("Nothing interesting found, not doing daemon-reload.");
                if (r > 0)
                        r = do_daemon_reload();
                return r;
        }

        r = 0;

        /* Always honour root= and usr= in the kernel command line if we are in an initrd */
        if (in_initrd()) {
                RET_GATHER(r, add_sysroot_mount());

                RET_GATHER(r, add_sysroot_usr_mount_or_fallback());

                RET_GATHER(r, add_volatile_root());
        } else
                RET_GATHER(r, add_volatile_var());

        /* Honour /etc/fstab only when that's enabled */
        if (arg_fstab_enabled) {
                /* Parse the local /etc/fstab, possibly from the initrd */
                RET_GATHER(r, parse_fstab(/* prefix_sysroot = */ false));

                /* If running in the initrd also parse the /etc/fstab from the host */
                if (in_initrd())
                        RET_GATHER(r, parse_fstab(/* prefix_sysroot = */ true));
                else
                        RET_GATHER(r, generator_enable_remount_fs_service(arg_dest));
        }

        RET_GATHER(r, add_mounts_from_cmdline());

        RET_GATHER(r, add_mounts_from_creds(/* prefix_sysroot = */ false));

        if (in_initrd())
                RET_GATHER(r, add_mounts_from_creds(/* prefix_sysroot = */ true));

        return r;
}

static int run(int argc, char **argv) {
        arg_sysroot_check = invoked_as(argv, "systemd-sysroot-fstab-check");

        if (arg_sysroot_check) {
                /* Run as in systemd-sysroot-fstab-check mode */
                log_setup();

                if (strv_length(argv) > 1)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "This program takes no arguments.");
                if (!in_initrd())
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "This program is only useful in the initrd.");
        } else {
                /* Run in generator mode */
                log_setup_generator();

                if (!IN_SET(strv_length(argv), 2, 4))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "This program takes one or three arguments.");

                arg_dest = ASSERT_PTR(argv[1]);
                arg_dest_late = ASSERT_PTR(argv[argc > 3 ? 3 : 1]);
        }

        return run_generator();
}

DEFINE_MAIN_FUNCTION(run);
