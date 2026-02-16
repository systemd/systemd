/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-daemon.h"
#include "sd-event.h"

#include "alloc-util.h"
#include "btrfs-util.h"
#include "copy.h"
#include "curl-util.h"
#include "dissect-image.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "install-file.h"
#include "log.h"
#include "mkdir-label.h"
#include "path-util.h"
#include "pidref.h"
#include "pretty-print.h"
#include "process-util.h"
#include "pull-common.h"
#include "pull-job.h"
#include "pull-tar.h"
#include "ratelimit.h"
#include "rm-rf.h"
#include "string-util.h"
#include "terminal-util.h"
#include "time-util.h"
#include "tmpfile-util.h"
#include "uid-classification.h"
#include "web-util.h"

typedef enum TarProgress {
        TAR_DOWNLOADING,
        TAR_VERIFYING,
        TAR_FINALIZING,
        TAR_COPYING,
} TarProgress;

typedef struct TarPull {
        sd_event *event;
        CurlGlue *glue;

        ImportFlags flags;
        ImportVerify verify;
        char *image_root;

        PullJob *tar_job;
        PullJob *checksum_job;
        PullJob *signature_job;
        PullJob *settings_job;

        TarPullFinished on_finished;
        void *userdata;

        char *local;

        PidRef tar_pid;

        char *final_path;
        char *temp_path;

        char *settings_path;
        char *settings_temp_path;

        int tree_fd;
        int userns_fd;

        unsigned last_percent;
        RateLimit progress_ratelimit;
} TarPull;

TarPull* tar_pull_unref(TarPull *p) {
        if (!p)
                return NULL;

        pidref_done_sigkill_wait(&p->tar_pid);

        pull_job_unref(p->tar_job);
        pull_job_unref(p->checksum_job);
        pull_job_unref(p->signature_job);
        pull_job_unref(p->settings_job);

        curl_glue_unref(p->glue);
        sd_event_unref(p->event);

        if (p->temp_path) {
                import_remove_tree(p->temp_path, &p->userns_fd, p->flags);
                free(p->temp_path);
        }
        unlink_and_free(p->settings_temp_path);

        free(p->final_path);
        free(p->settings_path);
        free(p->image_root);
        free(p->local);

        safe_close(p->tree_fd);
        safe_close(p->userns_fd);

        return mfree(p);
}

int tar_pull_new(
                TarPull **ret,
                sd_event *event,
                const char *image_root,
                TarPullFinished on_finished,
                void *userdata) {

        _cleanup_(curl_glue_unrefp) CurlGlue *g = NULL;
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(tar_pull_unrefp) TarPull *p = NULL;
        _cleanup_free_ char *root = NULL;
        int r;

        assert(image_root);
        assert(ret);

        root = strdup(image_root);
        if (!root)
                return -ENOMEM;

        if (event)
                e = sd_event_ref(event);
        else {
                r = sd_event_default(&e);
                if (r < 0)
                        return r;
        }

        r = curl_glue_new(&g, e);
        if (r < 0)
                return r;

        p = new(TarPull, 1);
        if (!p)
                return -ENOMEM;

        *p = (TarPull) {
                .on_finished = on_finished,
                .userdata = userdata,
                .image_root = TAKE_PTR(root),
                .event = TAKE_PTR(e),
                .glue = TAKE_PTR(g),
                .tar_pid = PIDREF_NULL,
                .tree_fd = -EBADF,
                .userns_fd = -EBADF,
                .last_percent = UINT_MAX,
                .progress_ratelimit = { 100 * USEC_PER_MSEC, 1 },
        };

        p->glue->on_finished = pull_job_curl_on_finished;
        p->glue->userdata = p;

        *ret = TAKE_PTR(p);

        return 0;
}

static void tar_pull_report_progress(TarPull *p, TarProgress progress) {
        unsigned percent;

        assert(p);

        switch (progress) {

        case TAR_DOWNLOADING: {
                unsigned remain = 85;

                percent = 0;

                if (p->checksum_job) {
                        percent += p->checksum_job->progress_percent * 5 / 100;
                        remain -= 5;
                }

                if (p->signature_job) {
                        percent += p->signature_job->progress_percent * 5 / 100;
                        remain -= 5;
                }

                if (p->settings_job) {
                        percent += p->settings_job->progress_percent * 5 / 100;
                        remain -= 5;
                }

                if (p->tar_job)
                        percent += p->tar_job->progress_percent * remain / 100;
                break;
        }

        case TAR_VERIFYING:
                percent = 85;
                break;

        case TAR_FINALIZING:
                percent = 90;
                break;

        case TAR_COPYING:
                percent = 95;
                break;

        default:
                assert_not_reached();
        }

        if (percent == p->last_percent)
                return;

        if (!ratelimit_below(&p->progress_ratelimit))
                return;

        sd_notifyf(false, "X_IMPORT_PROGRESS=%u%%", percent);

        if (isatty_safe(STDERR_FILENO))
                draw_progress_bar("Total:", percent);

        log_debug("Combined progress %u%%", percent);

        p->last_percent = percent;
}

static int tar_pull_determine_path(
                TarPull *p,
                const char *suffix,
                char **field /* input + output (!) */) {
        int r;

        assert(p);
        assert(field);

        if (*field)
                return 0;

        assert(p->tar_job);

        r = pull_make_path(p->tar_job->url, p->tar_job->etag, p->image_root, ".tar-", suffix, field);
        if (r < 0)
                return log_oom();

        return 1;
}

static int tar_pull_make_local_copy(TarPull *p) {
        _cleanup_(rm_rf_subvolume_and_freep) char *t = NULL;
        _cleanup_free_ char *path = NULL;
        const char *source;
        int r;

        assert(p);
        assert(p->tar_job);

        if (!p->local)
                return 0;

        /* Creates a copy/clone of the original downloaded version (which is supposed to remain untouched)
         * under a local image name (which may then be modified) */

        assert(p->final_path);

        path = path_join(p->image_root, p->local);
        if (!path)
                return log_oom();

        if (FLAGS_SET(p->flags, IMPORT_PULL_KEEP_DOWNLOAD)) {
                r = tempfn_random(path, NULL, &t);
                if (r < 0)
                        return log_error_errno(r, "Failed to generate temporary filename for %s: %m", path);

                if (FLAGS_SET(p->flags, IMPORT_FOREIGN_UID)) {
                        /* Copy in userns */

                        r = import_make_foreign_userns(&p->userns_fd);
                        if (r < 0)
                                return r;

                        /* Usually, tar_pull_job_on_open_disk_tar() would allocate ->tree_fd for us, but if
                         * already downloaded the image before, and are just making a copy of the original
                         * download, we need to open ->tree_fd now */
                        if (p->tree_fd < 0) {
                                _cleanup_close_ int directory_fd = open(p->final_path, O_DIRECTORY|O_CLOEXEC);
                                if (directory_fd < 0)
                                        return log_error_errno(errno, "Failed to open '%s': %m", p->final_path);

                                struct stat st;
                                if (fstat(directory_fd, &st) < 0)
                                        return log_error_errno(errno, "Failed to stat '%s': %m", p->final_path);

                                if (!uid_is_foreign(st.st_uid))
                                        return log_error_errno(
                                                        SYNTHETIC_ERRNO(EINVAL),
                                                        "Image tree '%s' is not owned by the foreign UID range, refusing.",
                                                        p->final_path);

                                r = mountfsd_mount_directory_fd(directory_fd, p->userns_fd, DISSECT_IMAGE_FOREIGN_UID, &p->tree_fd);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to mount directory via mountfsd: %m");
                        }

                        _cleanup_close_ int directory_fd = -EBADF;
                        r = mountfsd_make_directory(t, MODE_INVALID, /* flags= */ 0, &directory_fd);
                        if (r < 0)
                                return log_error_errno(r, "Failed to make directory via mountfsd: %m");

                        _cleanup_close_ int copy_fd = -EBADF;
                        r = mountfsd_mount_directory_fd(directory_fd, p->userns_fd, DISSECT_IMAGE_FOREIGN_UID, &copy_fd);
                        if (r < 0)
                                return log_error_errno(r, "Failed to mount directory via mountfsd: %m");

                        r = copy_tree_at_foreign(p->tree_fd, copy_fd, p->userns_fd);
                        if (r < 0)
                                return r;
                } else {
                        /* Copy locally */
                        if (p->flags & IMPORT_BTRFS_SUBVOL)
                                r = btrfs_subvol_snapshot_at(
                                                AT_FDCWD, p->final_path,
                                                AT_FDCWD, t,
                                                (p->flags & IMPORT_BTRFS_QUOTA ? BTRFS_SNAPSHOT_QUOTA : 0)|
                                                BTRFS_SNAPSHOT_FALLBACK_COPY|
                                                BTRFS_SNAPSHOT_FALLBACK_DIRECTORY|
                                                BTRFS_SNAPSHOT_RECURSIVE);
                        else
                                r = copy_tree(p->final_path, t, UID_INVALID, GID_INVALID, COPY_REFLINK|COPY_HARDLINKS, NULL, NULL);
                        if (r < 0)
                                return log_error_errno(r, "Failed to create original download image: %m");
                }

                source = t;
        } else
                source = p->final_path;

        r = install_file(AT_FDCWD, source,
                         AT_FDCWD, path,
                         (p->flags & IMPORT_FORCE ? INSTALL_REPLACE : 0) |
                         (p->flags & IMPORT_READ_ONLY ? INSTALL_READ_ONLY|INSTALL_GRACEFUL : 0) |
                         (p->flags & IMPORT_SYNC ? INSTALL_SYNCFS|INSTALL_GRACEFUL : 0));
        if (r < 0)
                return log_error_errno(r, "Failed to install local image '%s': %m", path);

        t = mfree(t);

        clear_progress_bar(/* prefix= */ NULL);
        log_info("Created new local image '%s'.", p->local);

        if (FLAGS_SET(p->flags, IMPORT_PULL_SETTINGS)) {
                _cleanup_free_ char *local_settings = NULL;
                assert(p->settings_job);

                r = tar_pull_determine_path(p, ".nspawn", &p->settings_path);
                if (r < 0)
                        return r;

                local_settings = strjoin(p->image_root, "/", p->local, ".nspawn");
                if (!local_settings)
                        return log_oom();

                if (FLAGS_SET(p->flags, IMPORT_PULL_KEEP_DOWNLOAD))
                        r = copy_file_atomic(
                                        p->settings_path,
                                        local_settings,
                                        0664,
                                        COPY_REFLINK |
                                        (FLAGS_SET(p->flags, IMPORT_FORCE) ? COPY_REPLACE : 0) |
                                        (FLAGS_SET(p->flags, IMPORT_SYNC) ? COPY_FSYNC_FULL : 0));
                else
                        r = install_file(AT_FDCWD, p->settings_path,
                                         AT_FDCWD, local_settings,
                                         (p->flags & IMPORT_FORCE ? INSTALL_REPLACE : 0) |
                                         (p->flags & IMPORT_SYNC ? INSTALL_SYNCFS : 0));
                if (r == -EEXIST)
                        log_warning_errno(r, "Settings file %s already exists, not replacing.", local_settings);
                else if (r == -ENOENT)
                        log_debug_errno(r, "Skipping creation of settings file, since none was found.");
                else if (r < 0)
                        log_warning_errno(r, "Failed to install settings files %s, ignoring: %m", local_settings);
                else
                        log_info("Created new settings file %s.", local_settings);
        }

        return 0;
}

static bool tar_pull_is_done(TarPull *p) {
        assert(p);
        assert(p->tar_job);

        if (!PULL_JOB_IS_COMPLETE(p->tar_job))
                return false;
        if (p->checksum_job && !PULL_JOB_IS_COMPLETE(p->checksum_job))
                return false;
        if (p->signature_job && !PULL_JOB_IS_COMPLETE(p->signature_job))
                return false;
        if (p->settings_job && !PULL_JOB_IS_COMPLETE(p->settings_job))
                return false;

        return true;
}

static void tar_pull_job_on_finished(PullJob *j) {
        int r;

        assert(j);
        TarPull *p = ASSERT_PTR(j->userdata);

        if (j->error != 0) {
                clear_progress_bar(/* prefix= */ NULL);

                if (j == p->tar_job) {
                        if (j->error == ENOMEDIUM) /* HTTP 404 */
                                r = log_error_errno(j->error, "Failed to retrieve image file. (Wrong URL?)");
                        else
                                r = log_error_errno(j->error, "Failed to retrieve image file.");
                        goto finish;
                } else if (j == p->checksum_job) {
                        r = log_error_errno(j->error, "Failed to retrieve SHA256 checksum, cannot verify. (Try --verify=no?)");
                        goto finish;
                } else if (j == p->signature_job)
                        log_debug_errno(j->error, "Signature job for %s failed, proceeding for now.", j->url);
                else if (j == p->settings_job)
                        log_info_errno(j->error, "Settings file could not be retrieved, proceeding without.");
                else
                        assert("unexpected job");
        }

        /* This is invoked if either the download completed successfully, or the download was skipped because
         * we already have the etag. */

        if (!tar_pull_is_done(p))
                return;

        if (p->signature_job && p->signature_job->error != 0) {
                VerificationStyle style;

                assert(p->checksum_job);

                r = verification_style_from_url(p->checksum_job->url, &style);
                if (r < 0) {
                        log_error_errno(r, "Failed to determine verification style from checksum URL: %m");
                        goto finish;
                }

                if (style == VERIFICATION_PER_DIRECTORY) { /* A failed signature file download only matters
                                                            * in per-directory verification mode, since only
                                                            * then the signature is detached, and thus a file
                                                            * of its own. */
                        r = log_error_errno(p->signature_job->error,
                                            "Failed to retrieve signature file, cannot verify. (Try --verify=no?)");
                        goto finish;
                }
        }

        pull_job_close_disk_fd(p->tar_job);
        pull_job_close_disk_fd(p->settings_job);

        if (pidref_is_set(&p->tar_pid)) {
                r = pidref_wait_for_terminate_and_check("tar", &p->tar_pid, WAIT_LOG);
                if (r < 0)
                        goto finish;
                pidref_done(&p->tar_pid);
                if (r != EXIT_SUCCESS) {
                        r = -EIO;
                        goto finish;
                }
        }

        if (!p->tar_job->etag_exists) {
                /* This is a new download, verify it, and move it into place */

                tar_pull_report_progress(p, TAR_VERIFYING);

                clear_progress_bar(/* prefix= */ NULL);
                r = pull_verify(p->verify,
                                p->tar_job,
                                p->checksum_job,
                                p->signature_job,
                                p->settings_job,
                                /* roothash_job= */ NULL,
                                /* roothash_signature_job= */ NULL,
                                /* verity_job= */ NULL);
                if (r < 0)
                        goto finish;
        }

        if (p->flags & IMPORT_DIRECT) {
                assert(!p->settings_job);
                assert(p->local);
                assert(!p->temp_path);

                tar_pull_report_progress(p, TAR_FINALIZING);

                r = import_mangle_os_tree_fd(p->tree_fd, p->userns_fd, p->flags);
                if (r < 0)
                        goto finish;

                r = install_file(
                                AT_FDCWD, p->local,
                                AT_FDCWD, NULL,
                                (p->flags & IMPORT_READ_ONLY ? INSTALL_READ_ONLY|INSTALL_GRACEFUL : 0) |
                                (p->flags & IMPORT_SYNC ? INSTALL_SYNCFS|INSTALL_GRACEFUL : 0));
                if (r < 0) {
                        log_error_errno(r, "Failed to finalize '%s': %m", p->local);
                        goto finish;
                }
        } else {
                r = tar_pull_determine_path(p, NULL, &p->final_path);
                if (r < 0)
                        goto finish;

                if (!p->tar_job->etag_exists) {
                        /* This is a new download, verify it, and move it into place */

                        assert(p->temp_path);
                        assert(p->final_path);

                        tar_pull_report_progress(p, TAR_FINALIZING);

                        r = import_mangle_os_tree_fd(p->tree_fd, p->userns_fd, p->flags);
                        if (r < 0)
                                goto finish;

                        r = install_file(
                                        AT_FDCWD, p->temp_path,
                                        AT_FDCWD, p->final_path,
                                        (p->flags & IMPORT_PULL_KEEP_DOWNLOAD ? INSTALL_READ_ONLY|INSTALL_GRACEFUL : 0) |
                                        (p->flags & IMPORT_SYNC ? INSTALL_SYNCFS|INSTALL_GRACEFUL : 0));
                        if (r < 0) {
                                log_error_errno(r, "Failed to rename to final image name to %s: %m", p->final_path);
                                goto finish;
                        }

                        p->temp_path = mfree(p->temp_path);

                        if (p->settings_job &&
                            p->settings_job->error == 0) {

                                /* Also move the settings file into place, if it exists. Note that we do so only if we also
                                 * moved the tar file in place, to keep things strictly in sync. */
                                assert(p->settings_temp_path);

                                /* Regenerate final name for this auxiliary file, we might know the etag of the file now, and
                                 * we should incorporate it in the file name if we can */
                                p->settings_path = mfree(p->settings_path);

                                r = tar_pull_determine_path(p, ".nspawn", &p->settings_path);
                                if (r < 0)
                                        goto finish;

                                r = install_file(
                                                AT_FDCWD, p->settings_temp_path,
                                                AT_FDCWD, p->settings_path,
                                                INSTALL_READ_ONLY|INSTALL_GRACEFUL|
                                                (p->flags & IMPORT_SYNC ? INSTALL_FSYNC_FULL : 0));
                                if (r < 0) {
                                        log_error_errno(r, "Failed to rename settings file to %s: %m", p->settings_path);
                                        goto finish;
                                }

                                p->settings_temp_path = mfree(p->settings_temp_path);
                        }
                }

                tar_pull_report_progress(p, TAR_COPYING);

                r = tar_pull_make_local_copy(p);
                if (r < 0)
                        goto finish;
        }

        r = 0;

finish:
        if (p->on_finished)
                p->on_finished(p, r, p->userdata);
        else
                sd_event_exit(p->event, r);
}

static int tar_pull_job_on_open_disk_tar(PullJob *j) {
        const char *where;
        int r;

        assert(j);

        TarPull *p = ASSERT_PTR(j->userdata);
        assert(p->tar_job == j);
        assert(!pidref_is_set(&p->tar_pid));
        assert(p->tree_fd < 0);

        if (p->flags & IMPORT_DIRECT)
                where = p->local;
        else {
                if (!p->temp_path) {
                        r = tempfn_random_child(p->image_root, "tar", &p->temp_path);
                        if (r < 0)
                                return log_oom();
                }

                where = p->temp_path;
        }

        (void) mkdir_parents_label(where, 0700);

        if (FLAGS_SET(p->flags, IMPORT_DIRECT|IMPORT_FORCE))
                (void) rm_rf(where, REMOVE_ROOT|REMOVE_PHYSICAL|REMOVE_SUBVOLUME);

        if (FLAGS_SET(p->flags, IMPORT_FOREIGN_UID)) {
                r = import_make_foreign_userns(&p->userns_fd);
                if (r < 0)
                        return r;

                _cleanup_close_ int directory_fd = -EBADF;
                r = mountfsd_make_directory(where, MODE_INVALID, /* flags= */ 0, &directory_fd);
                if (r < 0)
                        return log_error_errno(r, "Failed to make directory via mountfsd: %m");

                r = mountfsd_mount_directory_fd(directory_fd, p->userns_fd, DISSECT_IMAGE_FOREIGN_UID, &p->tree_fd);
                if (r < 0)
                        return log_error_errno(r, "Failed to mount directory via mountfsd: %m");
        } else {
                if (p->flags & IMPORT_BTRFS_SUBVOL)
                        r = btrfs_subvol_make_fallback(AT_FDCWD, where, 0755);
                else
                        r = RET_NERRNO(mkdir(where, 0755));
                if (r == -EEXIST && (p->flags & IMPORT_DIRECT)) /* EEXIST is OK if in direct mode, but not otherwise,
                                                                 * because in that case our temporary path collided */
                        r = 0;
                if (r < 0)
                        return log_error_errno(r, "Failed to create directory/subvolume %s: %m", where);

                if (r > 0 && (p->flags & IMPORT_BTRFS_QUOTA)) { /* actually btrfs subvol */
                        if (!(p->flags & IMPORT_DIRECT))
                                (void) import_assign_pool_quota_and_warn(p->image_root);
                        (void) import_assign_pool_quota_and_warn(where);
                }

                p->tree_fd = open(where, O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
                if (p->tree_fd < 0)
                        return log_error_errno(errno, "Failed to open '%s': %m", where);
        }

        j->disk_fd = import_fork_tar_x(p->tree_fd, p->userns_fd, &p->tar_pid);
        if (j->disk_fd < 0)
                return j->disk_fd;

        return 0;
}

static int tar_pull_job_on_open_disk_settings(PullJob *j) {
        TarPull *p;
        int r;

        assert(j);
        assert(j->userdata);

        p = j->userdata;
        assert(p->settings_job == j);

        if (!p->settings_temp_path) {
                r = tempfn_random_child(p->image_root, "settings", &p->settings_temp_path);
                if (r < 0)
                        return log_oom();
        }

        (void) mkdir_parents_label(p->settings_temp_path, 0700);

        j->disk_fd = open(p->settings_temp_path, O_RDWR|O_CREAT|O_EXCL|O_NOCTTY|O_CLOEXEC, 0664);
        if (j->disk_fd < 0)
                return log_error_errno(errno, "Failed to create %s: %m", p->settings_temp_path);

        return 0;
}

static void tar_pull_job_on_progress(PullJob *j) {
        TarPull *p;

        assert(j);
        assert(j->userdata);

        p = j->userdata;

        tar_pull_report_progress(p, TAR_DOWNLOADING);
}

int tar_pull_start(
                TarPull *p,
                const char *url,
                const char *local,
                ImportFlags flags,
                ImportVerify verify,
                const struct iovec *checksum) {

        int r;

        assert(p);
        assert(verify == _IMPORT_VERIFY_INVALID || verify < _IMPORT_VERIFY_MAX);
        assert(verify == _IMPORT_VERIFY_INVALID || verify >= 0);
        assert((verify < 0) || !iovec_is_set(checksum));
        assert(!(flags & ~IMPORT_PULL_FLAGS_MASK_TAR));
        assert(!(flags & IMPORT_PULL_SETTINGS) || !(flags & IMPORT_DIRECT));
        assert(!(flags & IMPORT_PULL_SETTINGS) || !iovec_is_set(checksum));

        if (!http_url_is_valid(url) && !file_url_is_valid(url))
                return -EINVAL;

        if (local && !pull_validate_local(local, flags))
                return -EINVAL;

        if (p->tar_job)
                return -EBUSY;

        r = free_and_strdup(&p->local, local);
        if (r < 0)
                return r;

        p->flags = flags;
        p->verify = verify;

        /* Set up download job for TAR file */
        r = pull_job_new(&p->tar_job, url, p->glue, p);
        if (r < 0)
                return r;

        p->tar_job->on_finished = tar_pull_job_on_finished;
        p->tar_job->on_open_disk = tar_pull_job_on_open_disk_tar;

        if (iovec_is_set(checksum)) {
                if (!iovec_memdup(checksum, &p->tar_job->expected_checksum))
                        return -ENOMEM;

                p->tar_job->calc_checksum = true;
        } else
                p->tar_job->calc_checksum = verify != IMPORT_VERIFY_NO;

        if (!FLAGS_SET(flags, IMPORT_DIRECT)) {
                r = pull_find_old_etags(url, p->image_root, DT_DIR, ".tar-", NULL, &p->tar_job->old_etags);
                if (r < 0)
                        return r;
        }

        /* Set up download of checksum/signature files */
        r = pull_make_verification_jobs(
                        &p->checksum_job,
                        &p->signature_job,
                        verify,
                        url,
                        p->glue,
                        tar_pull_job_on_finished,
                        p);
        if (r < 0)
                return r;

        /* Set up download job for the settings file (.nspawn) */
        if (FLAGS_SET(flags, IMPORT_PULL_SETTINGS)) {
                r = pull_make_auxiliary_job(
                                &p->settings_job,
                                url,
                                tar_strip_suffixes,
                                ".nspawn",
                                verify,
                                p->glue,
                                tar_pull_job_on_open_disk_settings,
                                tar_pull_job_on_finished,
                                p);
                if (r < 0)
                        return r;
        }

        PullJob *j;
        FOREACH_ARGUMENT(j,
                         p->tar_job,
                         p->checksum_job,
                         p->signature_job,
                         p->settings_job) {

                if (!j)
                        continue;

                j->on_progress = tar_pull_job_on_progress;
                j->sync = FLAGS_SET(flags, IMPORT_SYNC);

                r = pull_job_begin(j);
                if (r < 0)
                        return r;
        }

        return 0;
}
