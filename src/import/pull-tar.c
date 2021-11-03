/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <curl/curl.h>
#include <sys/prctl.h>

#include "sd-daemon.h"

#include "alloc-util.h"
#include "btrfs-util.h"
#include "copy.h"
#include "curl-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "hostname-util.h"
#include "import-common.h"
#include "import-util.h"
#include "install-file.h"
#include "macro.h"
#include "mkdir.h"
#include "path-util.h"
#include "process-util.h"
#include "pull-common.h"
#include "pull-job.h"
#include "pull-tar.h"
#include "rm-rf.h"
#include "string-util.h"
#include "strv.h"
#include "tmpfile-util.h"
#include "user-util.h"
#include "utf8.h"
#include "util.h"
#include "web-util.h"

typedef enum TarProgress {
        TAR_DOWNLOADING,
        TAR_VERIFYING,
        TAR_FINALIZING,
        TAR_COPYING,
} TarProgress;

struct TarPull {
        sd_event *event;
        CurlGlue *glue;

        PullFlags flags;
        ImportVerify verify;
        char *image_root;

        PullJob *tar_job;
        PullJob *checksum_job;
        PullJob *signature_job;
        PullJob *settings_job;

        TarPullFinished on_finished;
        void *userdata;

        char *local;

        pid_t tar_pid;

        char *final_path;
        char *temp_path;

        char *settings_path;
        char *settings_temp_path;

        char *checksum;
};

TarPull* tar_pull_unref(TarPull *i) {
        if (!i)
                return NULL;

        if (i->tar_pid > 1) {
                (void) kill_and_sigcont(i->tar_pid, SIGKILL);
                (void) wait_for_terminate(i->tar_pid, NULL);
        }

        pull_job_unref(i->tar_job);
        pull_job_unref(i->checksum_job);
        pull_job_unref(i->signature_job);
        pull_job_unref(i->settings_job);

        curl_glue_unref(i->glue);
        sd_event_unref(i->event);

        rm_rf_subvolume_and_free(i->temp_path);
        unlink_and_free(i->settings_temp_path);

        free(i->final_path);
        free(i->settings_path);
        free(i->image_root);
        free(i->local);
        free(i->checksum);

        return mfree(i);
}

int tar_pull_new(
                TarPull **ret,
                sd_event *event,
                const char *image_root,
                TarPullFinished on_finished,
                void *userdata) {

        _cleanup_(curl_glue_unrefp) CurlGlue *g = NULL;
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(tar_pull_unrefp) TarPull *i = NULL;
        _cleanup_free_ char *root = NULL;
        int r;

        assert(ret);

        root = strdup(image_root ?: "/var/lib/machines");
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

        i = new(TarPull, 1);
        if (!i)
                return -ENOMEM;

        *i = (TarPull) {
                .on_finished = on_finished,
                .userdata = userdata,
                .image_root = TAKE_PTR(root),
                .event = TAKE_PTR(e),
                .glue = TAKE_PTR(g),
        };

        i->glue->on_finished = pull_job_curl_on_finished;
        i->glue->userdata = i;

        *ret = TAKE_PTR(i);

        return 0;
}

static void tar_pull_report_progress(TarPull *i, TarProgress p) {
        unsigned percent;

        assert(i);

        switch (p) {

        case TAR_DOWNLOADING: {
                unsigned remain = 85;

                percent = 0;

                if (i->checksum_job) {
                        percent += i->checksum_job->progress_percent * 5 / 100;
                        remain -= 5;
                }

                if (i->signature_job) {
                        percent += i->signature_job->progress_percent * 5 / 100;
                        remain -= 5;
                }

                if (i->settings_job) {
                        percent += i->settings_job->progress_percent * 5 / 100;
                        remain -= 5;
                }

                if (i->tar_job)
                        percent += i->tar_job->progress_percent * remain / 100;
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

        sd_notifyf(false, "X_IMPORT_PROGRESS=%u", percent);
        log_debug("Combined progress %u%%", percent);
}

static int tar_pull_determine_path(
                TarPull *i,
                const char *suffix,
                char **field /* input + output (!) */) {
        int r;

        assert(i);
        assert(field);

        if (*field)
                return 0;

        assert(i->tar_job);

        r = pull_make_path(i->tar_job->url, i->tar_job->etag, i->image_root, ".tar-", suffix, field);
        if (r < 0)
                return log_oom();

        return 1;
}

static int tar_pull_make_local_copy(TarPull *i) {
        _cleanup_(rm_rf_subvolume_and_freep) char *t = NULL;
        const char *p;
        int r;

        assert(i);
        assert(i->tar_job);

        if (!i->local)
                return 0;

        assert(i->final_path);

        p = prefix_roota(i->image_root, i->local);

        r = tempfn_random(p, NULL, &t);
        if (r < 0)
                return log_error_errno(r, "Failed to generate temporary filename for %s: %m", p);

        if (i->flags & PULL_BTRFS_SUBVOL)
                r = btrfs_subvol_snapshot(
                                i->final_path,
                                t,
                                (i->flags & PULL_BTRFS_QUOTA ? BTRFS_SNAPSHOT_QUOTA : 0)|
                                BTRFS_SNAPSHOT_FALLBACK_COPY|
                                BTRFS_SNAPSHOT_FALLBACK_DIRECTORY|
                                BTRFS_SNAPSHOT_RECURSIVE);
        else
                r = copy_tree(i->final_path, t, UID_INVALID, GID_INVALID, COPY_REFLINK|COPY_HARDLINKS);
        if (r < 0)
                return log_error_errno(r, "Failed to create local image: %m");

        r = install_file(AT_FDCWD, t,
                         AT_FDCWD, p,
                         (i->flags & PULL_FORCE ? INSTALL_REPLACE : 0) |
                         (i->flags & PULL_READ_ONLY ? INSTALL_READ_ONLY : 0) |
                         (i->flags & PULL_SYNC ? INSTALL_SYNCFS : 0));
        if (r < 0)
                return log_error_errno(r, "Failed to install local image '%s': %m", p);

        t = mfree(t);

        log_info("Created new local image '%s'.", i->local);

        if (FLAGS_SET(i->flags, PULL_SETTINGS)) {
                const char *local_settings;
                assert(i->settings_job);

                r = tar_pull_determine_path(i, ".nspawn", &i->settings_path);
                if (r < 0)
                        return r;

                local_settings = strjoina(i->image_root, "/", i->local, ".nspawn");

                r = copy_file_atomic(
                                i->settings_path,
                                local_settings,
                                0664,
                                0, 0,
                                COPY_REFLINK |
                                (FLAGS_SET(i->flags, PULL_FORCE) ? COPY_REPLACE : 0) |
                                (FLAGS_SET(i->flags, PULL_SYNC) ? COPY_FSYNC_FULL : 0));
                if (r == -EEXIST)
                        log_warning_errno(r, "Settings file %s already exists, not replacing.", local_settings);
                else if (r == -ENOENT)
                        log_debug_errno(r, "Skipping creation of settings file, since none was found.");
                else if (r < 0)
                        log_warning_errno(r, "Failed to copy settings files %s, ignoring: %m", local_settings);
                else
                        log_info("Created new settings file %s.", local_settings);
        }

        return 0;
}

static bool tar_pull_is_done(TarPull *i) {
        assert(i);
        assert(i->tar_job);

        if (!PULL_JOB_IS_COMPLETE(i->tar_job))
                return false;
        if (i->checksum_job && !PULL_JOB_IS_COMPLETE(i->checksum_job))
                return false;
        if (i->signature_job && !PULL_JOB_IS_COMPLETE(i->signature_job))
                return false;
        if (i->settings_job && !PULL_JOB_IS_COMPLETE(i->settings_job))
                return false;

        return true;
}

static void tar_pull_job_on_finished(PullJob *j) {
        TarPull *i;
        int r;

        assert(j);
        assert(j->userdata);

        i = j->userdata;

        if (j->error != 0) {
                if (j == i->tar_job) {
                        if (j->error == ENOMEDIUM) /* HTTP 404 */
                                r = log_error_errno(j->error, "Failed to retrieve image file. (Wrong URL?)");
                        else
                                r = log_error_errno(j->error, "Failed to retrieve image file.");
                        goto finish;
                } else if (j == i->checksum_job) {
                        r = log_error_errno(j->error, "Failed to retrieve SHA256 checksum, cannot verify. (Try --verify=no?)");
                        goto finish;
                } else if (j == i->signature_job)
                        log_debug_errno(j->error, "Signature job for %s failed, proceeding for now.", j->url);
                else if (j == i->settings_job)
                        log_info_errno(j->error, "Settings file could not be retrieved, proceeding without.");
                else
                        assert("unexpected job");
        }

        /* This is invoked if either the download completed successfully, or the download was skipped because
         * we already have the etag. */

        if (!tar_pull_is_done(i))
                return;

        if (i->signature_job && i->signature_job->error != 0) {
                VerificationStyle style;

                assert(i->checksum_job);

                r = verification_style_from_url(i->checksum_job->url, &style);
                if (r < 0) {
                        log_error_errno(r, "Failed to determine verification style from checksum URL: %m");
                        goto finish;
                }

                if (style == VERIFICATION_PER_DIRECTORY) { /* A failed signature file download only matters
                                                            * in per-directory verification mode, since only
                                                            * then the signature is detached, and thus a file
                                                            * of its own. */
                        r = log_error_errno(i->signature_job->error,
                                            "Failed to retrieve signature file, cannot verify. (Try --verify=no?)");
                        goto finish;
                }
        }

        pull_job_close_disk_fd(i->tar_job);
        pull_job_close_disk_fd(i->settings_job);

        if (i->tar_pid > 0) {
                r = wait_for_terminate_and_check("tar", TAKE_PID(i->tar_pid), WAIT_LOG);
                if (r < 0)
                        goto finish;
                if (r != EXIT_SUCCESS) {
                        r = -EIO;
                        goto finish;
                }
        }

        if (!i->tar_job->etag_exists) {
                /* This is a new download, verify it, and move it into place */

                tar_pull_report_progress(i, TAR_VERIFYING);

                r = pull_verify(i->verify,
                                i->checksum,
                                i->tar_job,
                                i->checksum_job,
                                i->signature_job,
                                i->settings_job,
                                /* roothash_job = */ NULL,
                                /* roothash_signature_job = */ NULL,
                                /* verity_job = */ NULL);
                if (r < 0)
                        goto finish;
        }

        if (i->flags & PULL_DIRECT) {
                assert(!i->settings_job);
                assert(i->local);
                assert(!i->temp_path);

                tar_pull_report_progress(i, TAR_FINALIZING);

                r = import_mangle_os_tree(i->local);
                if (r < 0)
                        goto finish;

                r = install_file(
                                AT_FDCWD, i->local,
                                AT_FDCWD, NULL,
                                (i->flags & PULL_READ_ONLY) ? INSTALL_READ_ONLY : 0 |
                                (i->flags & PULL_SYNC ? INSTALL_SYNCFS : 0));
                if (r < 0) {
                        log_error_errno(r, "Failed to finalize '%s': %m", i->local);
                        goto finish;
                }
        } else {
                r = tar_pull_determine_path(i, NULL, &i->final_path);
                if (r < 0)
                        goto finish;

                if (!i->tar_job->etag_exists) {
                        /* This is a new download, verify it, and move it into place */

                        assert(i->temp_path);
                        assert(i->final_path);

                        tar_pull_report_progress(i, TAR_FINALIZING);

                        r = import_mangle_os_tree(i->temp_path);
                        if (r < 0)
                                goto finish;

                        r = install_file(
                                        AT_FDCWD, i->temp_path,
                                        AT_FDCWD, i->final_path,
                                        INSTALL_READ_ONLY|
                                        (i->flags & PULL_SYNC ? INSTALL_SYNCFS : 0));
                        if (r < 0) {
                                log_error_errno(r, "Failed to rename to final image name to %s: %m", i->final_path);
                                goto finish;
                        }

                        i->temp_path = mfree(i->temp_path);

                        if (i->settings_job &&
                            i->settings_job->error == 0) {

                                /* Also move the settings file into place, if it exists. Note that we do so only if we also
                                 * moved the tar file in place, to keep things strictly in sync. */
                                assert(i->settings_temp_path);

                                /* Regenerate final name for this auxiliary file, we might know the etag of the file now, and
                                 * we should incorporate it in the file name if we can */
                                i->settings_path = mfree(i->settings_path);

                                r = tar_pull_determine_path(i, ".nspawn", &i->settings_path);
                                if (r < 0)
                                        goto finish;

                                r = install_file(
                                                AT_FDCWD, i->settings_temp_path,
                                                AT_FDCWD, i->settings_path,
                                                INSTALL_READ_ONLY|
                                                (i->flags & PULL_SYNC ? INSTALL_FSYNC_FULL : 0));
                                if (r < 0) {
                                        log_error_errno(r, "Failed to rename settings file to %s: %m", i->settings_path);
                                        goto finish;
                                }

                                i->settings_temp_path = mfree(i->settings_temp_path);
                        }
                }

                tar_pull_report_progress(i, TAR_COPYING);

                r = tar_pull_make_local_copy(i);
                if (r < 0)
                        goto finish;
        }

        r = 0;

finish:
        if (i->on_finished)
                i->on_finished(i, r, i->userdata);
        else
                sd_event_exit(i->event, r);
}

static int tar_pull_job_on_open_disk_tar(PullJob *j) {
        const char *where;
        TarPull *i;
        int r;

        assert(j);
        assert(j->userdata);

        i = j->userdata;
        assert(i->tar_job == j);
        assert(i->tar_pid <= 0);

        if (i->flags & PULL_DIRECT)
                where = i->local;
        else {
                if (!i->temp_path) {
                        r = tempfn_random_child(i->image_root, "tar", &i->temp_path);
                        if (r < 0)
                                return log_oom();
                }

                where = i->temp_path;
        }

        (void) mkdir_parents_label(where, 0700);

        if (FLAGS_SET(i->flags, PULL_DIRECT|PULL_FORCE))
                (void) rm_rf(where, REMOVE_ROOT|REMOVE_PHYSICAL|REMOVE_SUBVOLUME);

        if (i->flags & PULL_BTRFS_SUBVOL)
                r = btrfs_subvol_make_fallback(where, 0755);
        else
                r = mkdir(where, 0755) < 0 ? -errno : 0;
        if (r == -EEXIST && (i->flags & PULL_DIRECT)) /* EEXIST is OK if in direct mode, but not otherwise,
                                                       * because in that case our temporary path collided */
                r = 0;
        if (r < 0)
                return log_error_errno(r, "Failed to create directory/subvolume %s: %m", where);
        if (r > 0 && (i->flags & PULL_BTRFS_QUOTA)) { /* actually btrfs subvol */
                if (!(i->flags & PULL_DIRECT))
                        (void) import_assign_pool_quota_and_warn(i->image_root);
                (void) import_assign_pool_quota_and_warn(where);
        }

        j->disk_fd = import_fork_tar_x(where, &i->tar_pid);
        if (j->disk_fd < 0)
                return j->disk_fd;

        return 0;
}

static int tar_pull_job_on_open_disk_settings(PullJob *j) {
        TarPull *i;
        int r;

        assert(j);
        assert(j->userdata);

        i = j->userdata;
        assert(i->settings_job == j);

        if (!i->settings_temp_path) {
                r = tempfn_random_child(i->image_root, "settings", &i->settings_temp_path);
                if (r < 0)
                        return log_oom();
        }

        (void) mkdir_parents_label(i->settings_temp_path, 0700);

        j->disk_fd = open(i->settings_temp_path, O_RDWR|O_CREAT|O_EXCL|O_NOCTTY|O_CLOEXEC, 0664);
        if (j->disk_fd < 0)
                return log_error_errno(errno, "Failed to create %s: %m", i->settings_temp_path);

        return 0;
}

static void tar_pull_job_on_progress(PullJob *j) {
        TarPull *i;

        assert(j);
        assert(j->userdata);

        i = j->userdata;

        tar_pull_report_progress(i, TAR_DOWNLOADING);
}

int tar_pull_start(
                TarPull *i,
                const char *url,
                const char *local,
                PullFlags flags,
                ImportVerify verify,
                const char *checksum) {

        PullJob *j;
        int r;

        assert(i);
        assert(verify == _IMPORT_VERIFY_INVALID || verify < _IMPORT_VERIFY_MAX);
        assert(verify == _IMPORT_VERIFY_INVALID || verify >= 0);
        assert((verify < 0) || !checksum);
        assert(!(flags & ~PULL_FLAGS_MASK_TAR));
        assert(!(flags & PULL_SETTINGS) || !(flags & PULL_DIRECT));
        assert(!(flags & PULL_SETTINGS) || !checksum);

        if (!http_url_is_valid(url) && !file_url_is_valid(url))
                return -EINVAL;

        if (local && !pull_validate_local(local, flags))
                return -EINVAL;

        if (i->tar_job)
                return -EBUSY;

        r = free_and_strdup(&i->local, local);
        if (r < 0)
                return r;

        r = free_and_strdup(&i->checksum, checksum);
        if (r < 0)
                return r;

        i->flags = flags;
        i->verify = verify;

        /* Set up download job for TAR file */
        r = pull_job_new(&i->tar_job, url, i->glue, i);
        if (r < 0)
                return r;

        i->tar_job->on_finished = tar_pull_job_on_finished;
        i->tar_job->on_open_disk = tar_pull_job_on_open_disk_tar;
        i->tar_job->calc_checksum = checksum || IN_SET(verify, IMPORT_VERIFY_CHECKSUM, IMPORT_VERIFY_SIGNATURE);

        if (!FLAGS_SET(flags, PULL_DIRECT)) {
                r = pull_find_old_etags(url, i->image_root, DT_DIR, ".tar-", NULL, &i->tar_job->old_etags);
                if (r < 0)
                        return r;
        }

        /* Set up download of checksum/signature files */
        r = pull_make_verification_jobs(
                        &i->checksum_job,
                        &i->signature_job,
                        verify,
                        checksum,
                        url,
                        i->glue,
                        tar_pull_job_on_finished,
                        i);
        if (r < 0)
                return r;

        /* Set up download job for the settings file (.nspawn) */
        if (FLAGS_SET(flags, PULL_SETTINGS)) {
                r = pull_make_auxiliary_job(
                                &i->settings_job,
                                url,
                                tar_strip_suffixes,
                                ".nspawn",
                                verify,
                                i->glue,
                                tar_pull_job_on_open_disk_settings,
                                tar_pull_job_on_finished,
                                i);
                if (r < 0)
                        return r;
        }

        FOREACH_POINTER(j,
                        i->tar_job,
                        i->checksum_job,
                        i->signature_job,
                        i->settings_job) {

                if (!j)
                        continue;

                j->on_progress = tar_pull_job_on_progress;
                j->sync = FLAGS_SET(flags, PULL_SYNC);

                r = pull_job_begin(j);
                if (r < 0)
                        return r;
        }

        return 0;
}
