/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/mount.h>
#if WANT_LINUX_FS_H
#include <linux/fs.h>
#endif

#include "dirent-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "fs-util.h"
#include "homework-cifs.h"
#include "homework-mount.h"
#include "memfd-util.h"
#include "mkdir.h"
#include "mount-util.h"
#include "process-util.h"
#include "stat-util.h"
#include "strv.h"
#include "tmpfile-util.h"

int home_setup_cifs(
                UserRecord *h,
                HomeSetupFlags flags,
                HomeSetup *setup) {

        _cleanup_free_ char *chost = NULL, *cservice = NULL, *cdir = NULL, *chost_and_service = NULL, *j = NULL, *options = NULL;
        int r;

        assert(h);
        assert(user_record_storage(h) == USER_CIFS);
        assert(setup);
        assert(!setup->undo_mount);
        assert(setup->root_fd < 0);

        if (FLAGS_SET(flags, HOME_SETUP_ALREADY_ACTIVATED)) {
                setup->root_fd = open(user_record_home_directory(h), O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW);
                if (setup->root_fd < 0)
                        return log_error_errno(errno, "Failed to open home directory: %m");

                return 0;
        }

        if (!h->cifs_service)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "User record lacks CIFS service, refusing.");

        r = parse_cifs_service(h->cifs_service, &chost, &cservice, &cdir);
        if (r < 0)
                return log_error_errno(r, "Failed parse CIFS service specification: %m");

        /* Just the host and service part, without the directory */
        chost_and_service = strjoin("//", chost, "/", cservice);
        if (!chost_and_service)
                return log_oom();

        if (asprintf(&options, "user=%s,uid=" UID_FMT ",forceuid,gid=" GID_FMT ",forcegid,file_mode=0%3o,dir_mode=0%3o",
                     user_record_cifs_user_name(h), h->uid, user_record_gid(h), user_record_access_mode(h),
                     user_record_access_mode(h)) < 0)
                return log_oom();

        if (h->cifs_domain)
                if (strextendf_with_separator(&options, ",", "domain=%s", h->cifs_domain) < 0)
                        return log_oom();

        if (h->cifs_extra_mount_options)
                if (!strextend_with_separator(&options, ",", h->cifs_extra_mount_options))
                        return log_oom();

        r = home_unshare_and_mkdir();
        if (r < 0)
                return r;

        STRV_FOREACH(pw, h->password) {
                _cleanup_close_ int passwd_fd = -EBADF;
                pid_t mount_pid;
                int exit_status;

                passwd_fd = memfd_new_and_seal_string("cifspw", *pw);
                if (passwd_fd < 0)
                        return log_error_errno(passwd_fd, "Failed to create data FD for password: %m");

                r = safe_fork("(mount)", FORK_RESET_SIGNALS|FORK_RLIMIT_NOFILE_SAFE|FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_STDOUT_TO_STDERR, &mount_pid);
                if (r < 0)
                        return r;
                if (r == 0) {
                        /* Child */

                        r = fd_cloexec(passwd_fd, false);
                        if (r < 0) {
                                log_error_errno(r, "Failed to disable CLOEXEC on password FD: %m");
                                _exit(EXIT_FAILURE);
                        }

                        r = setenvf("PASSWD_FD", /* overwrite= */ true, "%d", passwd_fd);
                        if (r < 0) {
                                log_error_errno(r, "Failed to set $PASSWD_FD: %m");
                                _exit(EXIT_FAILURE);
                        }

                        execl("/bin/mount", "/bin/mount", "-n", "-t", "cifs",
                              chost_and_service, HOME_RUNTIME_WORK_DIR,
                              "-o", options, NULL);

                        log_error_errno(errno, "Failed to execute mount: %m");
                        _exit(EXIT_FAILURE);
                }

                exit_status = wait_for_terminate_and_check("mount", mount_pid, WAIT_LOG_ABNORMAL|WAIT_LOG_NON_ZERO_EXIT_STATUS);
                if (exit_status < 0)
                        return exit_status;
                if (exit_status == EXIT_SUCCESS) {
                        setup->undo_mount = true;
                        break;
                }

                if (pw[1])
                        log_info("CIFS mount failed with password #%zu, trying next password.", (size_t) (pw - h->password) + 1);
        }

        if (!setup->undo_mount)
                return log_error_errno(SYNTHETIC_ERRNO(ENOKEY),
                                       "Failed to mount home directory, supplied password(s) possibly wrong.");

        /* Adjust MS_SUID and similar flags */
        r = mount_nofollow_verbose(LOG_ERR, NULL, HOME_RUNTIME_WORK_DIR, NULL, MS_BIND|MS_REMOUNT|user_record_mount_flags(h), NULL);
        if (r < 0)
                return r;

        if (cdir) {
                j = path_join(HOME_RUNTIME_WORK_DIR, cdir);
                if (!j)
                        return log_oom();

                if (FLAGS_SET(flags, HOME_SETUP_CIFS_MKDIR)) {
                        setup->root_fd = open_mkdir(j, O_CLOEXEC, 0700);
                        if (setup->root_fd < 0)
                                return log_error_errno(setup->root_fd, "Failed to create CIFS subdirectory: %m");
                }
        }

        if (setup->root_fd < 0) {
                setup->root_fd = open(j ?: HOME_RUNTIME_WORK_DIR, O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW);
                if (setup->root_fd < 0)
                        return log_error_errno(errno, "Failed to open home directory: %m");
        }

        setup->mount_suffix = TAKE_PTR(cdir);
        return 0;
}

int home_activate_cifs(
                UserRecord *h,
                HomeSetupFlags flags,
                HomeSetup *setup,
                PasswordCache *cache,
                UserRecord **ret_home) {

        _cleanup_(user_record_unrefp) UserRecord *new_home = NULL, *header_home = NULL;
        const char *hdo, *hd;
        int r;

        assert(h);
        assert(user_record_storage(h) == USER_CIFS);
        assert(setup);
        assert(ret_home);

        assert_se(hdo = user_record_home_directory(h));
        hd = strdupa_safe(hdo); /* copy the string out, since it might change later in the home record object */

        r = home_setup(h, 0, setup, cache, &header_home);
        if (r < 0)
                return r;

        r = home_refresh(h, flags, setup, header_home, cache, NULL, &new_home);
        if (r < 0)
                return r;

        setup->root_fd = safe_close(setup->root_fd);

        r = home_move_mount(setup->mount_suffix, hd);
        if (r < 0)
                return r;

        setup->undo_mount = false;
        setup->do_drop_caches = false;

        log_info("Everything completed.");

        *ret_home = TAKE_PTR(new_home);
        return 1;
}

int home_create_cifs(UserRecord *h, HomeSetup *setup, UserRecord **ret_home) {
        _cleanup_(user_record_unrefp) UserRecord *new_home = NULL;
        int r;

        assert(h);
        assert(user_record_storage(h) == USER_CIFS);
        assert(setup);
        assert(ret_home);

        if (!h->cifs_service)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "User record lacks CIFS service, refusing.");

        if (access("/sbin/mount.cifs", F_OK) < 0) {
                if (errno == ENOENT)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOLINK), "/sbin/mount.cifs is missing.");

                return log_error_errno(errno, "Unable to detect whether /sbin/mount.cifs exists: %m");
        }

        r = home_setup_cifs(h, HOME_SETUP_CIFS_MKDIR, setup);
        if (r < 0)
                return r;

        r = dir_is_empty_at(setup->root_fd, NULL, /* ignore_hidden_or_backup= */ false);
        if (r < 0)
                return log_error_errno(r, "Failed to detect if CIFS directory is empty: %m");
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTEMPTY), "Selected CIFS directory not empty, refusing.");

        r = home_populate(h, setup->root_fd);
        if (r < 0)
                return r;

        r = home_sync_and_statfs(setup->root_fd, NULL);
        if (r < 0)
                return r;

        r = user_record_clone(h, USER_RECORD_LOAD_MASK_SECRET|USER_RECORD_PERMISSIVE, &new_home);
        if (r < 0)
                return log_error_errno(r, "Failed to clone record: %m");

        r = user_record_add_binding(
                        new_home,
                        USER_CIFS,
                        NULL,
                        SD_ID128_NULL,
                        SD_ID128_NULL,
                        SD_ID128_NULL,
                        NULL,
                        NULL,
                        UINT64_MAX,
                        NULL,
                        NULL,
                        h->uid,
                        (gid_t) h->uid);
        if (r < 0)
                return log_error_errno(r, "Failed to add binding to record: %m");

        log_info("Everything completed.");

        *ret_home = TAKE_PTR(new_home);
        return 0;
}
