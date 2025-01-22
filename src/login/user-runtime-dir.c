/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdint.h>
#include <sys/mount.h>

#include "sd-bus.h"

#include "bus-error.h"
#include "bus-locator.h"
#include "dev-setup.h"
#include "devnum-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "fs-util.h"
#include "label-util.h"
#include "limits-util.h"
#include "main-func.h"
#include "missing_magic.h"
#include "missing_syscall.h"
#include "mkdir-label.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "path-util.h"
#include "quota-util.h"
#include "rm-rf.h"
#include "selinux-util.h"
#include "smack-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "user-util.h"
#include "userdb.h"

static int acquire_runtime_dir_properties(uint64_t *ret_size, uint64_t *ret_inodes) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        uint64_t size, inodes;
        int r;

        assert(ret_size);
        assert(ret_inodes);

        r = sd_bus_default_system(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to system bus: %m");

        r = bus_get_property_trivial(bus, bus_login_mgr, "RuntimeDirectorySize", &error, 't', &size);
        if (r < 0) {
                log_warning_errno(r, "Failed to acquire runtime directory size, ignoring: %s", bus_error_message(&error, r));
                sd_bus_error_free(&error);

                size = physical_memory_scale(10U, 100U); /* 10% */
        }

        r = bus_get_property_trivial(bus, bus_login_mgr, "RuntimeDirectoryInodesMax", &error, 't', &inodes);
        if (r < 0) {
                log_warning_errno(r, "Failed to acquire number of inodes for runtime directory, ignoring: %s", bus_error_message(&error, r));
                sd_bus_error_free(&error);

                inodes = DIV_ROUND_UP(size, 4096);
        }

        *ret_size = size;
        *ret_inodes = inodes;

        return 0;
}

static int user_mkdir_runtime_path(
                const char *runtime_path,
                uid_t uid,
                gid_t gid,
                uint64_t runtime_dir_size,
                uint64_t runtime_dir_inodes) {

        int r;

        assert(runtime_path);
        assert(path_is_absolute(runtime_path));
        assert(uid_is_valid(uid));
        assert(gid_is_valid(gid));

        r = mkdir_safe_label("/run/user", 0755, 0, 0, MKDIR_WARN_MODE);
        if (r < 0)
                return log_error_errno(r, "Failed to create /run/user: %m");

        if (path_is_mount_point(runtime_path) > 0)
                log_debug("%s is already a mount point", runtime_path);
        else {
                char options[STRLEN("mode=0700,uid=,gid=,size=,nr_inodes=,smackfsroot=*")
                             + DECIMAL_STR_MAX(uid_t)
                             + DECIMAL_STR_MAX(gid_t)
                             + DECIMAL_STR_MAX(uint64_t)
                             + DECIMAL_STR_MAX(uint64_t)];

                xsprintf(options,
                         "mode=0700,uid=" UID_FMT ",gid=" GID_FMT ",size=%" PRIu64 ",nr_inodes=%" PRIu64 "%s",
                         uid, gid, runtime_dir_size, runtime_dir_inodes,
                         mac_smack_use() ? ",smackfsroot=*" : "");

                _cleanup_free_ char *d = strdup(runtime_path);
                if (!d)
                        return log_oom();

                r = mkdir_label(runtime_path, 0700);
                if (r < 0 && r != -EEXIST)
                        return log_error_errno(r, "Failed to create %s: %m", runtime_path);

                _cleanup_(rmdir_and_freep) char *destroy = TAKE_PTR(d); /* auto-destroy */

                r = mount_nofollow_verbose(LOG_DEBUG, "tmpfs", runtime_path, "tmpfs", MS_NODEV|MS_NOSUID, options);
                if (r < 0) {
                        if (!ERRNO_IS_PRIVILEGE(r))
                                return log_error_errno(r, "Failed to mount per-user tmpfs directory %s: %m", runtime_path);

                        log_debug_errno(r,
                                        "Failed to mount per-user tmpfs directory %s.\n"
                                        "Assuming containerized execution, ignoring: %m", runtime_path);

                        r = chmod_and_chown(runtime_path, 0700, uid, gid);
                        if (r < 0)
                                return log_error_errno(r, "Failed to change ownership and mode of \"%s\": %m", runtime_path);
                }

                destroy = mfree(destroy); /* deactivate auto-destroy */

                r = label_fix(runtime_path, 0);
                if (r < 0)
                        log_warning_errno(r, "Failed to fix label of \"%s\", ignoring: %m", runtime_path);
        }

        return 0;
}

static int do_mount(UserRecord *ur) {
        int r;

        assert(ur);

        if (!uid_is_valid(ur->uid) || !gid_is_valid(ur->gid))
                return log_error_errno(SYNTHETIC_ERRNO(ENOMSG), "User '%s' lacks UID or GID, refusing.", ur->user_name);

        uint64_t runtime_dir_size, runtime_dir_inodes;
        r = acquire_runtime_dir_properties(&runtime_dir_size, &runtime_dir_inodes);
        if (r < 0)
                return r;

        char runtime_path[STRLEN("/run/user/") + DECIMAL_STR_MAX(uid_t)];
        xsprintf(runtime_path, "/run/user/" UID_FMT, ur->uid);

        log_debug("Will mount %s owned by "UID_FMT":"GID_FMT, runtime_path, ur->uid, ur->gid);
        return user_mkdir_runtime_path(runtime_path, ur->uid, ur->gid, runtime_dir_size, runtime_dir_inodes);
}

static int user_remove_runtime_path(const char *runtime_path) {
        int r;

        assert(runtime_path);
        assert(path_is_absolute(runtime_path));

        r = rm_rf(runtime_path, 0);
        if (r < 0)
                log_debug_errno(r, "Failed to remove runtime directory %s (before unmounting), ignoring: %m", runtime_path);

        /* Ignore cases where the directory isn't mounted, as that's quite possible, if we lacked the permissions to
         * mount something */
        r = RET_NERRNO(umount2(runtime_path, MNT_DETACH));
        if (r < 0 && !IN_SET(r, -EINVAL, -ENOENT))
                log_debug_errno(r, "Failed to unmount user runtime directory %s, ignoring: %m", runtime_path);

        r = rm_rf(runtime_path, REMOVE_ROOT);
        if (r < 0 && r != -ENOENT)
                return log_error_errno(r, "Failed to remove runtime directory %s (after unmounting): %m", runtime_path);

        return 0;
}

static int do_umount(const char *user) {
        char runtime_path[STRLEN("/run/user/") + DECIMAL_STR_MAX(uid_t)];
        uid_t uid;
        int r;

        /* The user may be already removed. So, first try to parse the string by parse_uid(),
         * and if it fails, fall back to get_user_creds(). */
        if (parse_uid(user, &uid) < 0) {
                r = get_user_creds(&user, &uid, NULL, NULL, NULL, 0);
                if (r < 0)
                        return log_error_errno(r,
                                               r == -ESRCH ? "No such user \"%s\"" :
                                               r == -ENOMSG ? "UID \"%s\" is invalid or has an invalid main group"
                                                            : "Failed to look up user \"%s\": %m",
                                               user);
        }

        xsprintf(runtime_path, "/run/user/" UID_FMT, uid);

        log_debug("Will remove %s", runtime_path);
        return user_remove_runtime_path(runtime_path);
}

static int apply_tmpfs_quota(
                char **paths,
                uid_t uid,
                uint64_t limit,
                uint32_t scale) {

        _cleanup_set_free_ Set *processed = NULL;
        int r;

        assert(uid_is_valid(uid));

        STRV_FOREACH(p, paths) {
                _cleanup_close_ int fd = open(*p, O_DIRECTORY|O_CLOEXEC);
                if (fd < 0) {
                        log_warning_errno(errno, "Failed to open '%s' in order to set quota, ignoring: %m", *p);
                        continue;
                }

                struct stat st;
                if (fstat(fd, &st) < 0) {
                        log_warning_errno(errno, "Failed to stat '%s' in order to set quota, ignoring: %m", *p);
                        continue;
                }

                /* Cover for bind mounted or symlinked /var/tmp/ + /tmp/ */
                if (set_contains(processed, DEVNUM_TO_PTR(st.st_dev))) {
                        log_debug("Not setting quota on '%s', since already processed.", *p);
                        continue;
                }

                /* Remember we already dealt with this fs, even if the subsequent operation fails, since
                 * there's no point in appyling quota twice, regardless if it succeeds or not. */
                if (set_ensure_put(&processed, /* hash_ops= */ NULL, DEVNUM_TO_PTR(st.st_dev)) < 0)
                        return log_oom();

                struct statfs sfs;
                if (fstatfs(fd, &sfs) < 0) {
                        log_warning_errno(errno, "Failed to statfs '%s' in order to set quota, ignoring: %m", *p);
                        continue;
                }

                if (!is_fs_type(&sfs, TMPFS_MAGIC)) {
                        log_debug("Not setting quota on '%s', since not tmpfs.", *p);
                        continue;
                }

                struct dqblk req;
                r = RET_NERRNO(quotactl_fd(fd, QCMD_FIXED(Q_GETQUOTA, USRQUOTA), uid, &req));
                if (r == -ESRCH)
                        zero(req);
                else if (ERRNO_IS_NEG_NOT_SUPPORTED(r)) {
                        log_debug_errno(r, "No UID quota support on %s, not setting quota: %m", *p);
                        continue;
                } else if (ERRNO_IS_NEG_PRIVILEGE(r)) {
                        log_debug_errno(r, "Lacking privileges to query UID quota on %s, not setting quota: %m", *p);
                        continue;
                } else if (r < 0) {
                        log_warning_errno(r, "Failed to query disk quota on %s for UID " UID_FMT ", ignoring: %m", *p, uid);
                        continue;
                }

                uint64_t v =
                        (scale == 0) ? 0 :
                        (scale == UINT32_MAX) ? UINT64_MAX :
                        (uint64_t) ((double) (sfs.f_blocks * sfs.f_frsize) / scale * UINT32_MAX);

                v = MIN(v, limit);
                v /= QIF_DQBLKSIZE;

                if (FLAGS_SET(req.dqb_valid, QIF_BLIMITS) && v == req.dqb_bhardlimit) {
                        /* Shortcut things if everything is set up properly already */
                        log_debug("Configured quota on '%s' already matches the intended setting, not updating quota.", *p);
                        continue;
                }

                req.dqb_valid = QIF_BLIMITS;
                req.dqb_bsoftlimit = req.dqb_bhardlimit = v;

                r = RET_NERRNO(quotactl_fd(fd, QCMD_FIXED(Q_SETQUOTA, USRQUOTA), uid, &req));
                if (r == -ESRCH) {
                        log_debug_errno(r, "Not setting UID quota on %s since UID quota is not supported: %m", *p);
                        continue;
                } else if (ERRNO_IS_NEG_PRIVILEGE(r)) {
                        log_debug_errno(r, "Lacking privileges to set UID quota on %s, skipping: %m", *p);
                        continue;
                } else if (r < 0) {
                        log_warning_errno(r, "Failed to set disk quota on %s for UID " UID_FMT ", ignoring: %m", *p, uid);
                        continue;
                }

                log_info("Successfully configured disk quota for UID " UID_FMT " on %s to %s", uid, *p, FORMAT_BYTES(v * QIF_DQBLKSIZE));
        }

        return 0;
}

static int do_tmpfs_quota(UserRecord *ur) {
        int r;

        assert(ur);

        if (user_record_is_root(ur)) {
                log_debug("Not applying tmpfs quota to root user.");
                return 0;
        }

        if (!uid_is_valid(ur->uid))
                return log_error_errno(SYNTHETIC_ERRNO(ENOMSG), "User '%s' lacks UID, refusing.", ur->user_name);

        r = apply_tmpfs_quota(STRV_MAKE("/tmp", "/var/tmp"), ur->uid, ur->tmp_limit.limit, user_record_tmp_limit_scale(ur));
        if (r < 0)
                return r;

        r = apply_tmpfs_quota(STRV_MAKE("/dev/shm"), ur->uid, ur->dev_shm_limit.limit, user_record_dev_shm_limit_scale(ur));
        if (r < 0)
                return r;

        return 0;
}

static int run(int argc, char *argv[]) {
        int r;

        log_setup();

        if (argc != 3)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "This program takes two arguments.");

        const char *verb = argv[1], *user = argv[2];

        if (!STR_IN_SET(verb, "start", "stop"))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "First argument must be either \"start\" or \"stop\".");

        umask(0022);

        r = mac_init();
        if (r < 0)
                return r;

        if (streq(verb, "start")) {
                _cleanup_(user_record_unrefp) UserRecord *ur = NULL;
                r = userdb_by_name(user, /* match= */ NULL, USERDB_PARSE_NUMERIC|USERDB_SUPPRESS_SHADOW, &ur);
                if (r == -ESRCH)
                        return log_error_errno(r, "User '%s' does not exist: %m", user);
                if (r < 0)
                        return log_error_errno(r, "Failed to resolve user '%s': %m", user);

                /* We do two things here: mount the per-user XDG_RUNTIME_DIR, and set up tmpfs quota on /tmp/
                 * and /dev/shm/. */

                r = 0;
                RET_GATHER(r, do_mount(ur));
                RET_GATHER(r, do_tmpfs_quota(ur));
                return r;
        }

        if (streq(verb, "stop"))
                return do_umount(user);

        assert_not_reached();
}

DEFINE_MAIN_FUNCTION(run);
