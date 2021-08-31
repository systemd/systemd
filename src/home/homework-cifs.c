/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dirent-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "fs-util.h"
#include "homework-cifs.h"
#include "homework-mount.h"
#include "mount-util.h"
#include "process-util.h"
#include "strv.h"
#include "tmpfile-util.h"

int home_prepare_cifs(
                UserRecord *h,
                bool already_activated,
                HomeSetup *setup) {

        assert(h);
        assert(setup);
        assert(user_record_storage(h) == USER_CIFS);

        if (already_activated)
                setup->root_fd = open(user_record_home_directory(h), O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW);
        else {
                bool mounted = false;
                char **pw;
                int r;

                r = home_unshare_and_mount(NULL, NULL, false, user_record_mount_flags(h));
                if (r < 0)
                        return r;

                STRV_FOREACH(pw, h->password) {
                        _cleanup_(unlink_and_freep) char *p = NULL;
                        _cleanup_free_ char *options = NULL;
                        _cleanup_(fclosep) FILE *f = NULL;
                        pid_t mount_pid;
                        int exit_status;

                        r = fopen_temporary(NULL, &f, &p);
                        if (r < 0)
                                return log_error_errno(r, "Failed to create temporary credentials file: %m");

                        fprintf(f,
                                "username=%s\n"
                                "password=%s\n",
                                user_record_cifs_user_name(h),
                                *pw);

                        if (h->cifs_domain)
                                fprintf(f, "domain=%s\n", h->cifs_domain);

                        r = fflush_and_check(f);
                        if (r < 0)
                                return log_error_errno(r, "Failed to write temporary credentials file: %m");

                        f = safe_fclose(f);

                        if (asprintf(&options, "credentials=%s,uid=" UID_FMT ",forceuid,gid=" GID_FMT ",forcegid,file_mode=0%3o,dir_mode=0%3o",
                                     p, h->uid, user_record_gid(h), user_record_access_mode(h), user_record_access_mode(h)) < 0)
                                return log_oom();

                        r = safe_fork("(mount)", FORK_RESET_SIGNALS|FORK_RLIMIT_NOFILE_SAFE|FORK_DEATHSIG|FORK_LOG|FORK_STDOUT_TO_STDERR, &mount_pid);
                        if (r < 0)
                                return r;
                        if (r == 0) {
                                /* Child */
                                execl("/bin/mount", "/bin/mount", "-n", "-t", "cifs",
                                      h->cifs_service, "/run/systemd/user-home-mount",
                                      "-o", options, NULL);

                                log_error_errno(errno, "Failed to execute mount: %m");
                                _exit(EXIT_FAILURE);
                        }

                        exit_status = wait_for_terminate_and_check("mount", mount_pid, WAIT_LOG_ABNORMAL|WAIT_LOG_NON_ZERO_EXIT_STATUS);
                        if (exit_status < 0)
                                return exit_status;
                        if (exit_status != EXIT_SUCCESS)
                                return -EPROTO;

                        mounted = true;
                        break;
                }

                if (!mounted)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOKEY),
                                               "Failed to mount home directory with supplied password.");

                setup->root_fd = open("/run/systemd/user-home-mount", O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW);
        }
        if (setup->root_fd < 0)
                return log_error_errno(errno, "Failed to open home directory: %m");

        return 0;
}

int home_activate_cifs(
                UserRecord *h,
                PasswordCache *cache,
                UserRecord **ret_home) {

        _cleanup_(home_setup_undo) HomeSetup setup = HOME_SETUP_INIT;
        _cleanup_(user_record_unrefp) UserRecord *new_home = NULL;
        const char *hdo, *hd;
        int r;

        assert(h);
        assert(user_record_storage(h) == USER_CIFS);
        assert(ret_home);

        if (!h->cifs_service)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "User record lacks CIFS service, refusing.");

        assert_se(hdo = user_record_home_directory(h));
        hd = strdupa(hdo); /* copy the string out, since it might change later in the home record object */

        r = home_prepare_cifs(h, false, &setup);
        if (r < 0)
                return r;

        r = home_refresh(h, &setup, NULL, cache, NULL, &new_home);
        if (r < 0)
                return r;

        setup.root_fd = safe_close(setup.root_fd);

        r = home_move_mount(NULL, hd);
        if (r < 0)
                return r;

        setup.undo_mount = false;

        log_info("Everything completed.");

        *ret_home = TAKE_PTR(new_home);
        return 1;
}

int home_create_cifs(UserRecord *h, UserRecord **ret_home) {
        _cleanup_(home_setup_undo) HomeSetup setup = HOME_SETUP_INIT;
        _cleanup_(user_record_unrefp) UserRecord *new_home = NULL;
        _cleanup_(closedirp) DIR *d = NULL;
        _cleanup_close_ int copy = -1;
        int r;

        assert(h);
        assert(user_record_storage(h) == USER_CIFS);
        assert(ret_home);

        if (!h->cifs_service)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "User record lacks CIFS service, refusing.");

        if (access("/sbin/mount.cifs", F_OK) < 0) {
                if (errno == ENOENT)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOLINK), "/sbin/mount.cifs is missing.");

                return log_error_errno(errno, "Unable to detect whether /sbin/mount.cifs exists: %m");
        }

        r = home_prepare_cifs(h, false, &setup);
        if (r < 0)
                return r;

        copy = fcntl(setup.root_fd, F_DUPFD_CLOEXEC, 3);
        if (copy < 0)
                return -errno;

        d = take_fdopendir(&copy);
        if (!d)
                return -errno;

        errno = 0;
        if (readdir_no_dot(d))
                return log_error_errno(SYNTHETIC_ERRNO(ENOTEMPTY), "Selected CIFS directory not empty, refusing.");
        if (errno != 0)
                return log_error_errno(errno, "Failed to detect if CIFS directory is empty: %m");

        r = home_populate(h, setup.root_fd);
        if (r < 0)
                return r;

        r = home_sync_and_statfs(setup.root_fd, NULL);
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
