/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "fstab-util.h"
#include "generator.h"
#include "log.h"
#include "main-func.h"
#include "mkdir.h"
#include "mount-setup.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "proc-cmdline.h"
#include "special.h"
#include "specifier.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "unit-name.h"
#include "util.h"
#include "virt.h"
#include "volatile-util.h"

typedef enum MountPointFlags {
        MOUNT_NOAUTO    = 1 << 0,
        MOUNT_NOFAIL    = 1 << 1,
        MOUNT_AUTOMOUNT = 1 << 2,
        MOUNT_MAKEFS    = 1 << 3,
        MOUNT_GROWFS    = 1 << 4,
        MOUNT_RW_ONLY   = 1 << 5,
} MountPointFlags;

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
static VolatileMode arg_volatile_mode = _VOLATILE_MODE_INVALID;

STATIC_DESTRUCTOR_REGISTER(arg_root_what, freep);
STATIC_DESTRUCTOR_REGISTER(arg_root_fstype, freep);
STATIC_DESTRUCTOR_REGISTER(arg_root_options, freep);
STATIC_DESTRUCTOR_REGISTER(arg_root_hash, freep);
STATIC_DESTRUCTOR_REGISTER(arg_usr_what, freep);
STATIC_DESTRUCTOR_REGISTER(arg_usr_fstype, freep);
STATIC_DESTRUCTOR_REGISTER(arg_usr_options, freep);

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
                const char *what,
                struct mntent *me,
                MountPointFlags flags) {

        _cleanup_free_ char *name = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(what);
        assert(me);

        if (!arg_swap_enabled) {
                log_info("Swap unit generation disabled on kernel command line, ignoring fstab swap entry for %s.", what);
                return 0;
        }

        if (access("/proc/swaps", F_OK) < 0) {
                log_info("Swap not supported, ignoring fstab swap entry for %s.", what);
                return 0;
        }

        if (detect_container() > 0) {
                log_info("Running in a container, ignoring fstab swap entry for %s.", what);
                return 0;
        }

        r = unit_name_from_path(what, ".swap", &name);
        if (r < 0)
                return log_error_errno(r, "Failed to generate unit name: %m");

        r = generator_open_unit_file(arg_dest, fstab_path(), name, &f);
        if (r < 0)
                return r;

        fprintf(f,
                "[Unit]\n"
                "Documentation=man:fstab(5) man:systemd-fstab-generator(8)\n"
                "SourcePath=%s\n",
                fstab_path());

        r = generator_write_blockdev_dependency(f, what);
        if (r < 0)
                return r;

        fprintf(f,
                "\n"
                "[Swap]\n");

        r = write_what(f, what);
        if (r < 0)
                return r;

        r = write_options(f, me->mnt_opts);
        if (r < 0)
                return r;

        r = fflush_and_check(f);
        if (r < 0)
                return log_error_errno(r, "Failed to write unit file %s: %m", name);

        /* use what as where, to have a nicer error message */
        r = generator_write_timeouts(arg_dest, what, what, me->mnt_opts, NULL);
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

        if (!(flags & MOUNT_NOAUTO)) {
                r = generator_add_symlink(arg_dest, SPECIAL_SWAP_TARGET,
                                          (flags & MOUNT_NOFAIL) ? "wants" : "requires", name);
                if (r < 0)
                        return r;
        }

        return 0;
}

static bool mount_is_network(struct mntent *me) {
        assert(me);

        return fstab_test_option(me->mnt_opts, "_netdev\0") ||
               fstype_is_network(me->mnt_type);
}

static bool mount_in_initrd(struct mntent *me) {
        assert(me);

        return fstab_test_option(me->mnt_opts, "x-initrd.mount\0") ||
               streq(me->mnt_dir, "/usr");
}

static int write_timeout(
                FILE *f,
                const char *where,
                const char *opts,
                const char *filter,
                const char *variable) {

        _cleanup_free_ char *timeout = NULL;
        char timespan[FORMAT_TIMESPAN_MAX];
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

        fprintf(f, "%s=%s\n", variable, format_timespan(timespan, sizeof(timespan), u, 0));

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
        char **s;
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

static int write_requires_mounts_for(FILE *f, const char *opts) {
        _cleanup_strv_free_ char **paths = NULL, **paths_escaped = NULL;
        _cleanup_free_ char *res = NULL;
        int r;

        assert(f);
        assert(opts);

        r = fstab_filter_options(opts, "x-systemd.requires-mounts-for\0", NULL, NULL, &paths, NULL);
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

        fprintf(f, "RequiresMountsFor=%s\n", res);

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
                r = write_requires_mounts_for(f, opts);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int add_mount(
                const char *dest,
                const char *what,
                const char *where,
                const char *original_where,
                const char *fstype,
                const char *opts,
                int passno,
                MountPointFlags flags,
                const char *post,
                const char *source) {

        _cleanup_free_ char
                *name = NULL,
                *automount_name = NULL,
                *filtered = NULL,
                *where_escaped = NULL;
        _cleanup_strv_free_ char **wanted_by = NULL, **required_by = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(what);
        assert(where);
        assert(opts);
        assert(post);
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

        r = fstab_filter_options(opts, "x-systemd.wanted-by\0", NULL, NULL, &wanted_by, NULL);
        if (r < 0)
                return r;

        r = fstab_filter_options(opts, "x-systemd.required-by\0", NULL, NULL, &required_by, NULL);
        if (r < 0)
                return r;

        if (path_equal(where, "/")) {
                if (flags & MOUNT_NOAUTO)
                        log_warning("Ignoring \"noauto\" option for root device");
                if (flags & MOUNT_NOFAIL)
                        log_warning("Ignoring \"nofail\" option for root device");
                if (flags & MOUNT_AUTOMOUNT)
                        log_warning("Ignoring \"automount\" option for root device");
                if (!strv_isempty(wanted_by))
                        log_warning("Ignoring \"x-systemd.wanted-by=\" option for root device");
                if (!strv_isempty(required_by))
                        log_warning("Ignoring \"x-systemd.required-by=\" option for root device");

                required_by = strv_free(required_by);
                wanted_by = strv_free(wanted_by);
                SET_FLAG(flags, MOUNT_NOAUTO | MOUNT_NOFAIL | MOUNT_AUTOMOUNT, false);
        }

        r = unit_name_from_path(where, ".mount", &name);
        if (r < 0)
                return log_error_errno(r, "Failed to generate unit name: %m");

        r = generator_open_unit_file(dest, fstab_path(), name, &f);
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

        /* Order the mount unit we generate relative to the post unit, so that DefaultDependencies= on the
         * target unit won't affect us. */
        if (post && !FLAGS_SET(flags, MOUNT_AUTOMOUNT) && !FLAGS_SET(flags, MOUNT_NOAUTO) &&
            !FLAGS_SET(flags, MOUNT_NOFAIL))
                fprintf(f, "Before=%s\n", post);

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

        if (original_where)
                fprintf(f, "# Canonicalized from %s\n", original_where);

        where_escaped = specifier_escape(where);
        if (!where_escaped)
                return log_oom();
        fprintf(f, "Where=%s\n", where_escaped);

        r = write_what(f, what);
        if (r < 0)
                return r;

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
                r = generator_hook_up_growfs(dest, where, post);
                if (r < 0)
                        return r;
        }

        if (!FLAGS_SET(flags, MOUNT_AUTOMOUNT)) {
                if (!FLAGS_SET(flags, MOUNT_NOAUTO) && strv_isempty(wanted_by) && strv_isempty(required_by)) {
                        r = generator_add_symlink(dest, post,
                                                  (flags & MOUNT_NOFAIL) ? "wants" : "requires", name);
                        if (r < 0)
                                return r;
                } else {
                        char **s;

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

                r = generator_open_unit_file(dest, fstab_path(), automount_name, &f);
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

                r = generator_add_symlink(dest, post,
                                          (flags & MOUNT_NOFAIL) ? "wants" : "requires", automount_name);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int parse_fstab(bool initrd) {
        _cleanup_endmntent_ FILE *f = NULL;
        const char *fstab;
        struct mntent *me;
        int r = 0;

        fstab = initrd ? "/sysroot/etc/fstab" : fstab_path();
        log_debug("Parsing %s...", fstab);

        f = setmntent(fstab, "re");
        if (!f) {
                if (errno == ENOENT)
                        return 0;

                return log_error_errno(errno, "Failed to open %s: %m", fstab);
        }

        while ((me = getmntent(f))) {
                _cleanup_free_ char *where = NULL, *what = NULL, *canonical_where = NULL;
                bool makefs, growfs, noauto, nofail;
                MountPointFlags flags;
                int k;

                if (initrd && !mount_in_initrd(me))
                        continue;

                what = fstab_node_to_udev_node(me->mnt_fsname);
                if (!what)
                        return log_oom();

                if (is_device_path(what) && path_is_read_only_fs("/sys") > 0) {
                        log_info("Running in a container, ignoring fstab device entry for %s.", what);
                        continue;
                }

                where = strdup(me->mnt_dir);
                if (!where)
                        return log_oom();

                if (is_path(where)) {
                        path_simplify(where);

                        /* Follow symlinks here; see 5261ba901845c084de5a8fd06500ed09bfb0bd80 which makes sense for
                         * mount units, but causes problems since it historically worked to have symlinks in e.g.
                         * /etc/fstab. So we canonicalize here. Note that we use CHASE_NONEXISTENT to handle the case
                         * where a symlink refers to another mount target; this works assuming the sub-mountpoint
                         * target is the final directory. */
                        k = chase_symlinks(where, initrd ? "/sysroot" : NULL,
                                           CHASE_PREFIX_ROOT | CHASE_NONEXISTENT,
                                           &canonical_where, NULL);
                        if (k < 0) /* If we can't canonicalize we continue on as if it wasn't a symlink */
                                log_debug_errno(k, "Failed to read symlink target for %s, ignoring: %m", where);
                        else if (streq(canonical_where, where)) /* If it was fully canonicalized, suppress the change */
                                canonical_where = mfree(canonical_where);
                        else
                                log_debug("Canonicalized what=%s where=%s to %s", what, where, canonical_where);
                }

                makefs = fstab_test_option(me->mnt_opts, "x-systemd.makefs\0");
                growfs = fstab_test_option(me->mnt_opts, "x-systemd.growfs\0");
                noauto = fstab_test_yes_no_option(me->mnt_opts, "noauto\0" "auto\0");
                nofail = fstab_test_yes_no_option(me->mnt_opts, "nofail\0" "fail\0");

                log_debug("Found entry what=%s where=%s type=%s makefs=%s growfs=%s noauto=%s nofail=%s",
                          what, where, me->mnt_type,
                          yes_no(makefs), yes_no(growfs),
                          yes_no(noauto), yes_no(nofail));

                flags = makefs * MOUNT_MAKEFS |
                        growfs * MOUNT_GROWFS |
                        noauto * MOUNT_NOAUTO |
                        nofail * MOUNT_NOFAIL;

                if (streq(me->mnt_type, "swap"))
                        k = add_swap(what, me, flags);
                else {
                        bool rw_only, automount;
                        const char *post;

                        rw_only = fstab_test_option(me->mnt_opts, "x-systemd.rw-only\0");
                        automount = fstab_test_option(me->mnt_opts,
                                                      "comment=systemd.automount\0"
                                                      "x-systemd.automount\0");

                        flags |= rw_only * MOUNT_RW_ONLY |
                                 automount * MOUNT_AUTOMOUNT;

                        if (initrd)
                                post = SPECIAL_INITRD_FS_TARGET;
                        else if (mount_is_network(me))
                                post = SPECIAL_REMOTE_FS_TARGET;
                        else
                                post = SPECIAL_LOCAL_FS_TARGET;

                        k = add_mount(arg_dest,
                                      what,
                                      canonical_where ?: where,
                                      canonical_where ? where: NULL,
                                      me->mnt_type,
                                      me->mnt_opts,
                                      me->mnt_passno,
                                      flags,
                                      post,
                                      fstab);
                }

                if (r >= 0 && k < 0)
                        r = k;
        }

        return r;
}

static int add_sysroot_mount(void) {
        _cleanup_free_ char *what = NULL;
        const char *opts, *fstype;
        bool default_rw;
        int r;

        if (isempty(arg_root_what)) {
                log_debug("Could not find a root= entry on the kernel command line.");
                return 0;
        }

        if (streq(arg_root_what, "gpt-auto")) {
                /* This is handled by the gpt-auto generator */
                log_debug("Skipping root directory handling, as gpt-auto was requested.");
                return 0;
        }

        if (path_equal(arg_root_what, "/dev/nfs")) {
                /* This is handled by the kernel or the initrd */
                log_debug("Skipping root directory handling, as /dev/nfs was requested.");
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

        if (is_device_path(what)) {
                r = generator_write_initrd_root_device_deps(arg_dest, what);
                if (r < 0)
                        return r;
        }

        return add_mount(arg_dest,
                         what,
                         "/sysroot",
                         NULL,
                         fstype,
                         opts,
                         is_device_path(what) ? 1 : 0, /* passno */
                         0,                            /* makefs off, growfs off, noauto off, nofail off, automount off */
                         SPECIAL_INITRD_ROOT_FS_TARGET,
                         "/proc/cmdline");
}

static int add_sysroot_usr_mount(void) {
        _cleanup_free_ char *what = NULL;
        const char *opts;
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
                log_debug("Could not find a usr= entry on the kernel command line.");
                return 0;
        }

        if (streq(arg_usr_what, "gpt-auto")) {
                /* This is handled by the gpt-auto generator */
                log_debug("Skipping /usr/ directory handling, as gpt-auto was requested.");
                return 1; /* systemd-gpt-auto-generator will generate a unit for this, hence report that a
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

        r = add_mount(arg_dest,
                      what,
                      "/sysusr/usr",
                      NULL,
                      arg_usr_fstype,
                      opts,
                      is_device_path(what) ? 1 : 0, /* passno */
                      0,
                      SPECIAL_INITRD_USR_FS_TARGET,
                      "/proc/cmdline");
        if (r < 0)
                return r;

        log_debug("Synthesizing entry what=/sysusr/usr where=/sysrootr/usr opts=bind");

        r = add_mount(arg_dest,
                      "/sysusr/usr",
                      "/sysroot/usr",
                      NULL,
                      NULL,
                      "bind",
                      0,
                      0,
                      SPECIAL_INITRD_FS_TARGET,
                      "/proc/cmdline");
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
         * themselves get the guarantee that /usr/ is definitely mounted somewhere. */

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

        return add_mount(arg_dest_late,
                         "tmpfs",
                         "/var",
                         NULL,
                         "tmpfs",
                         "mode=0755" TMPFS_LIMITS_VAR,
                         0,
                         0,
                         SPECIAL_LOCAL_FS_TARGET,
                         "/proc/cmdline");
}

static int parse_proc_cmdline_item(const char *key, const char *value, void *data) {
        int r;

        /* root=, usr=, usrfstype= and roofstype= may occur more than once, the last
         * instance should take precedence.  In the case of multiple rootflags=
         * or usrflags= the arguments should be concatenated */

        if (STR_IN_SET(key, "fstab", "rd.fstab")) {

                r = value ? parse_boolean(value) : 1;
                if (r < 0)
                        log_warning("Failed to parse fstab switch %s. Ignoring.", value);
                else
                        arg_fstab_enabled = r;

        } else if (streq(key, "root")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                return free_and_strdup_warn(&arg_root_what, value);

        } else if (streq(key, "rootfstype")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                return free_and_strdup_warn(&arg_root_fstype, value);

        } else if (streq(key, "rootflags")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                if (!strextend_with_separator(&arg_root_options, ",", value))
                        return log_oom();

        } else if (streq(key, "roothash")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                return free_and_strdup_warn(&arg_root_hash, value);

        } else if (streq(key, "mount.usr")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                return free_and_strdup_warn(&arg_usr_what, value);

        } else if (streq(key, "mount.usrfstype")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                return free_and_strdup_warn(&arg_usr_fstype, value);

        } else if (streq(key, "mount.usrflags")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                if (!strextend_with_separator(&arg_usr_options, ",", value))
                        return log_oom();

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
        }

        return 0;
}

static int determine_root(void) {
        /* If we have a root hash but no root device then Verity is used, and we use the "root" DM device as root. */

        if (arg_root_what)
                return 0;

        if (!arg_root_hash)
                return 0;

        arg_root_what = strdup("/dev/mapper/root");
        if (!arg_root_what)
                return log_oom();

        log_info("Using verity root device %s.", arg_root_what);

        return 1;
}

static int run(const char *dest, const char *dest_early, const char *dest_late) {
        int r, r2 = 0, r3 = 0;

        assert_se(arg_dest = dest);
        assert_se(arg_dest_late = dest_late);

        r = proc_cmdline_parse(parse_proc_cmdline_item, NULL, 0);
        if (r < 0)
                log_warning_errno(r, "Failed to parse kernel command line, ignoring: %m");

        (void) determine_root();

        /* Always honour root= and usr= in the kernel command line if we are in an initrd */
        if (in_initrd()) {
                r = add_sysroot_mount();

                r2 = add_sysroot_usr_mount_or_fallback();

                r3 = add_volatile_root();
        } else
                r = add_volatile_var();

        /* Honour /etc/fstab only when that's enabled */
        if (arg_fstab_enabled) {
                /* Parse the local /etc/fstab, possibly from the initrd */
                r2 = parse_fstab(false);

                /* If running in the initrd also parse the /etc/fstab from the host */
                if (in_initrd())
                        r3 = parse_fstab(true);
                else
                        r3 = generator_enable_remount_fs_service(arg_dest);
        }

        return r < 0 ? r : r2 < 0 ? r2 : r3;
}

DEFINE_MAIN_GENERATOR_FUNCTION(run);
