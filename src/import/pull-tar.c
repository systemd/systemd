/* SPDX-License-Identifier: LGPL-2.1+ */

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

        char *image_root;

        PullJob *tar_job;
        PullJob *settings_job;
        PullJob *checksum_job;
        PullJob *signature_job;

        TarPullFinished on_finished;
        void *userdata;

        char *local;
        bool force_local;
        bool settings;

        pid_t tar_pid;

        char *final_path;
        char *temp_path;

        char *settings_path;
        char *settings_temp_path;

        ImportVerify verify;
};

TarPull* tar_pull_unref(TarPull *i) {
        if (!i)
                return NULL;

        if (i->tar_pid > 1) {
                (void) kill_and_sigcont(i->tar_pid, SIGKILL);
                (void) wait_for_terminate(i->tar_pid, NULL);
        }

        pull_job_unref(i->tar_job);
        pull_job_unref(i->settings_job);
        pull_job_unref(i->checksum_job);
        pull_job_unref(i->signature_job);

        curl_glue_unref(i->glue);
        sd_event_unref(i->event);

        if (i->temp_path) {
                (void) rm_rf(i->temp_path, REMOVE_ROOT|REMOVE_PHYSICAL|REMOVE_SUBVOLUME);
                free(i->temp_path);
        }

        if (i->settings_temp_path) {
                (void) unlink(i->settings_temp_path);
                free(i->settings_temp_path);
        }

        free(i->final_path);
        free(i->settings_path);
        free(i->image_root);
        free(i->local);

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

                if (i->settings_job) {
                        percent += i->settings_job->progress_percent * 5 / 100;
                        remain -= 5;
                }

                if (i->checksum_job) {
                        percent += i->checksum_job->progress_percent * 5 / 100;
                        remain -= 5;
                }

                if (i->signature_job) {
                        percent += i->signature_job->progress_percent * 5 / 100;
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
                assert_not_reached("Unknown progress state");
        }

        sd_notifyf(false, "X_IMPORT_PROGRESS=%u", percent);
        log_debug("Combined progress %u%%", percent);
}

static int tar_pull_determine_path(TarPull *i, const char *suffix, char **field) {
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
        int r;

        assert(i);
        assert(i->tar_job);

        if (!i->local)
                return 0;

        r = pull_make_local_copy(i->final_path, i->image_root, i->local, i->force_local);
        if (r < 0)
                return r;

        if (i->settings) {
                const char *local_settings;
                assert(i->settings_job);

                r = tar_pull_determine_path(i, ".nspawn", &i->settings_path);
                if (r < 0)
                        return r;

                local_settings = strjoina(i->image_root, "/", i->local, ".nspawn");

                r = copy_file_atomic(i->settings_path, local_settings, 0664, 0, 0, COPY_REFLINK | (i->force_local ? COPY_REPLACE : 0));
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
        if (i->settings_job && !PULL_JOB_IS_COMPLETE(i->settings_job))
                return false;
        if (i->checksum_job && !PULL_JOB_IS_COMPLETE(i->checksum_job))
                return false;
        if (i->signature_job && !PULL_JOB_IS_COMPLETE(i->signature_job))
                return false;

        return true;
}

static void tar_pull_job_on_finished(PullJob *j) {
        TarPull *i;
        int r;

        assert(j);
        assert(j->userdata);

        i = j->userdata;

        if (j == i->settings_job) {
                if (j->error != 0)
                        log_info_errno(j->error, "Settings file could not be retrieved, proceeding without.");
        } else if (j->error != 0 && j != i->signature_job) {
                if (j == i->checksum_job)
                        log_error_errno(j->error, "Failed to retrieve SHA256 checksum, cannot verify. (Try --verify=no?)");
                else
                        log_error_errno(j->error, "Failed to retrieve image file. (Wrong URL?)");

                r = j->error;
                goto finish;
        }

        /* This is invoked if either the download completed
         * successfully, or the download was skipped because we
         * already have the etag. */

        if (!tar_pull_is_done(i))
                return;

        if (i->signature_job && i->checksum_job->style == VERIFICATION_PER_DIRECTORY && i->signature_job->error != 0) {
                log_error_errno(j->error, "Failed to retrieve signature file, cannot verify. (Try --verify=no?)");

                r = i->signature_job->error;
                goto finish;
        }

        i->tar_job->disk_fd = safe_close(i->tar_job->disk_fd);
        if (i->settings_job)
                i->settings_job->disk_fd = safe_close(i->settings_job->disk_fd);

        r = tar_pull_determine_path(i, NULL, &i->final_path);
        if (r < 0)
                goto finish;

        if (i->tar_pid > 0) {
                r = wait_for_terminate_and_check("tar", i->tar_pid, WAIT_LOG);
                i->tar_pid = 0;
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

                r = pull_verify(i->tar_job, NULL, i->settings_job, i->checksum_job, i->signature_job);
                if (r < 0)
                        goto finish;

                tar_pull_report_progress(i, TAR_FINALIZING);

                r = import_make_read_only(i->temp_path);
                if (r < 0)
                        goto finish;

                r = rename_noreplace(AT_FDCWD, i->temp_path, AT_FDCWD, i->final_path);
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

                        r = import_make_read_only(i->settings_temp_path);
                        if (r < 0)
                                goto finish;

                        r = rename_noreplace(AT_FDCWD, i->settings_temp_path, AT_FDCWD, i->settings_path);
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

        r = 0;

finish:
        if (i->on_finished)
                i->on_finished(i, r, i->userdata);
        else
                sd_event_exit(i->event, r);
}

static int tar_pull_job_on_open_disk_tar(PullJob *j) {
        TarPull *i;
        int r;

        assert(j);
        assert(j->userdata);

        i = j->userdata;
        assert(i->tar_job == j);
        assert(i->tar_pid <= 0);

        if (!i->temp_path) {
                r = tempfn_random_child(i->image_root, "tar", &i->temp_path);
                if (r < 0)
                        return log_oom();
        }

        mkdir_parents_label(i->temp_path, 0700);

        r = btrfs_subvol_make(i->temp_path);
        if (r == -ENOTTY) {
                if (mkdir(i->temp_path, 0755) < 0)
                        return log_error_errno(errno, "Failed to create directory %s: %m", i->temp_path);
        } else if (r < 0)
                return log_error_errno(r, "Failed to create subvolume %s: %m", i->temp_path);
        else
                (void) import_assign_pool_quota_and_warn(i->temp_path);

        j->disk_fd = import_fork_tar_x(i->temp_path, &i->tar_pid);
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

        mkdir_parents_label(i->settings_temp_path, 0700);

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
                bool force_local,
                ImportVerify verify,
                bool settings) {

        int r;

        assert(i);
        assert(verify < _IMPORT_VERIFY_MAX);
        assert(verify >= 0);

        if (!http_url_is_valid(url))
                return -EINVAL;

        if (local && !machine_name_is_valid(local))
                return -EINVAL;

        if (i->tar_job)
                return -EBUSY;

        r = free_and_strdup(&i->local, local);
        if (r < 0)
                return r;

        i->force_local = force_local;
        i->verify = verify;
        i->settings = settings;

        /* Set up download job for TAR file */
        r = pull_job_new(&i->tar_job, url, i->glue, i);
        if (r < 0)
                return r;

        i->tar_job->on_finished = tar_pull_job_on_finished;
        i->tar_job->on_open_disk = tar_pull_job_on_open_disk_tar;
        i->tar_job->on_progress = tar_pull_job_on_progress;
        i->tar_job->calc_checksum = verify != IMPORT_VERIFY_NO;

        r = pull_find_old_etags(url, i->image_root, DT_DIR, ".tar-", NULL, &i->tar_job->old_etags);
        if (r < 0)
                return r;

        /* Set up download job for the settings file (.nspawn) */
        if (settings) {
                r = pull_make_auxiliary_job(&i->settings_job, url, tar_strip_suffixes, ".nspawn", i->glue, tar_pull_job_on_finished, i);
                if (r < 0)
                        return r;

                i->settings_job->on_open_disk = tar_pull_job_on_open_disk_settings;
                i->settings_job->on_progress = tar_pull_job_on_progress;
                i->settings_job->calc_checksum = verify != IMPORT_VERIFY_NO;
        }

        /* Set up download of checksum/signature files */
        r = pull_make_verification_jobs(&i->checksum_job, &i->signature_job, verify, url, i->glue, tar_pull_job_on_finished, i);
        if (r < 0)
                return r;

        r = pull_job_begin(i->tar_job);
        if (r < 0)
                return r;

        if (i->settings_job) {
                r = pull_job_begin(i->settings_job);
                if (r < 0)
                        return r;
        }

        if (i->checksum_job) {
                i->checksum_job->on_progress = tar_pull_job_on_progress;
                i->checksum_job->style = VERIFICATION_PER_FILE;

                r = pull_job_begin(i->checksum_job);
                if (r < 0)
                        return r;
        }

        if (i->signature_job) {
                i->signature_job->on_progress = tar_pull_job_on_progress;

                r = pull_job_begin(i->signature_job);
                if (r < 0)
                        return r;
        }

        return 0;
}
