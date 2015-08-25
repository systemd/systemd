/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2015 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <sys/prctl.h>
#include <curl/curl.h>

#include "sd-daemon.h"
#include "utf8.h"
#include "strv.h"
#include "copy.h"
#include "btrfs-util.h"
#include "util.h"
#include "macro.h"
#include "mkdir.h"
#include "rm-rf.h"
#include "path-util.h"
#include "process-util.h"
#include "hostname-util.h"
#include "import-util.h"
#include "import-common.h"
#include "curl-util.h"
#include "pull-job.h"
#include "pull-common.h"
#include "pull-tar.h"

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
        PullJob *checksum_job;
        PullJob *signature_job;

        TarPullFinished on_finished;
        void *userdata;

        char *local;
        bool force_local;
        bool grow_machine_directory;

        pid_t tar_pid;

        char *temp_path;
        char *final_path;

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
        pull_job_unref(i->checksum_job);
        pull_job_unref(i->signature_job);

        curl_glue_unref(i->glue);
        sd_event_unref(i->event);

        if (i->temp_path) {
                (void) rm_rf(i->temp_path, REMOVE_ROOT|REMOVE_PHYSICAL|REMOVE_SUBVOLUME);
                free(i->temp_path);
        }

        free(i->final_path);
        free(i->image_root);
        free(i->local);
        free(i);

        return NULL;
}

int tar_pull_new(
                TarPull **ret,
                sd_event *event,
                const char *image_root,
                TarPullFinished on_finished,
                void *userdata) {

        _cleanup_(tar_pull_unrefp) TarPull *i = NULL;
        int r;

        assert(ret);
        assert(event);

        i = new0(TarPull, 1);
        if (!i)
                return -ENOMEM;

        i->on_finished = on_finished;
        i->userdata = userdata;

        i->image_root = strdup(image_root ?: "/var/lib/machines");
        if (!i->image_root)
                return -ENOMEM;

        i->grow_machine_directory = path_startswith(i->image_root, "/var/lib/machines");

        i->event = sd_event_ref(event);

        r = curl_glue_new(&i->glue, i->event);
        if (r < 0)
                return r;

        i->glue->on_finished = pull_job_curl_on_finished;
        i->glue->userdata = i;

        *ret = i;
        i = NULL;

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

static int tar_pull_make_local_copy(TarPull *i) {
        int r;

        assert(i);
        assert(i->tar_job);

        if (!i->local)
                return 0;

        if (!i->final_path) {
                r = pull_make_path(i->tar_job->url, i->tar_job->etag, i->image_root, ".tar-", NULL, &i->final_path);
                if (r < 0)
                        return log_oom();
        }

        r = pull_make_local_copy(i->final_path, i->image_root, i->local, i->force_local);
        if (r < 0)
                return r;

        return 0;
}

static bool tar_pull_is_done(TarPull *i) {
        assert(i);
        assert(i->tar_job);

        if (i->tar_job->state != PULL_JOB_DONE)
                return false;
        if (i->checksum_job && i->checksum_job->state != PULL_JOB_DONE)
                return false;
        if (i->signature_job && i->signature_job->state != PULL_JOB_DONE)
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
                if (j == i->checksum_job)
                        log_error_errno(j->error, "Failed to retrieve SHA256 checksum, cannot verify. (Try --verify=no?)");
                else if (j == i->signature_job)
                        log_error_errno(j->error, "Failed to retrieve signature file, cannot verify. (Try --verify=no?)");
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

        j->disk_fd = safe_close(i->tar_job->disk_fd);

        if (i->tar_pid > 0) {
                r = wait_for_terminate_and_warn("tar", i->tar_pid, true);
                i->tar_pid = 0;
                if (r < 0)
                        goto finish;
        }

        if (!i->tar_job->etag_exists) {
                /* This is a new download, verify it, and move it into place */

                tar_pull_report_progress(i, TAR_VERIFYING);

                r = pull_verify(i->tar_job, i->checksum_job, i->signature_job);
                if (r < 0)
                        goto finish;

                tar_pull_report_progress(i, TAR_FINALIZING);

                r = import_make_read_only(i->temp_path);
                if (r < 0)
                        goto finish;

                r = rename_noreplace(AT_FDCWD, i->temp_path, AT_FDCWD, i->final_path);
                if (r < 0) {
                        log_error_errno(r, "Failed to rename to final image name: %m");
                        goto finish;
                }

                free(i->temp_path);
                i->temp_path = NULL;
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

static int tar_pull_job_on_open_disk(PullJob *j) {
        TarPull *i;
        int r;

        assert(j);
        assert(j->userdata);

        i = j->userdata;
        assert(i->tar_job == j);
        assert(!i->final_path);
        assert(!i->temp_path);
        assert(i->tar_pid <= 0);

        r = pull_make_path(j->url, j->etag, i->image_root, ".tar-", NULL, &i->final_path);
        if (r < 0)
                return log_oom();

        r = tempfn_random(i->final_path, NULL, &i->temp_path);
        if (r < 0)
                return log_oom();

        mkdir_parents_label(i->temp_path, 0700);

        r = btrfs_subvol_make(i->temp_path);
        if (r == -ENOTTY) {
                if (mkdir(i->temp_path, 0755) < 0)
                        return log_error_errno(errno, "Failed to create directory %s: %m", i->temp_path);
        } else if (r < 0)
                return log_error_errno(errno, "Failed to create subvolume %s: %m", i->temp_path);

        j->disk_fd = import_fork_tar_x(i->temp_path, &i->tar_pid);
        if (j->disk_fd < 0)
                return j->disk_fd;

        return 0;
}

static void tar_pull_job_on_progress(PullJob *j) {
        TarPull *i;

        assert(j);
        assert(j->userdata);

        i = j->userdata;

        tar_pull_report_progress(i, TAR_DOWNLOADING);
}

int tar_pull_start(TarPull *i, const char *url, const char *local, bool force_local, ImportVerify verify) {
        int r;

        assert(i);

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

        r = pull_job_new(&i->tar_job, url, i->glue, i);
        if (r < 0)
                return r;

        i->tar_job->on_finished = tar_pull_job_on_finished;
        i->tar_job->on_open_disk = tar_pull_job_on_open_disk;
        i->tar_job->on_progress = tar_pull_job_on_progress;
        i->tar_job->calc_checksum = verify != IMPORT_VERIFY_NO;
        i->tar_job->grow_machine_directory = i->grow_machine_directory;

        r = pull_find_old_etags(url, i->image_root, DT_DIR, ".tar-", NULL, &i->tar_job->old_etags);
        if (r < 0)
                return r;

        r = pull_make_verification_jobs(&i->checksum_job, &i->signature_job, verify, url, i->glue, tar_pull_job_on_finished, i);
        if (r < 0)
                return r;

        r = pull_job_begin(i->tar_job);
        if (r < 0)
                return r;

        if (i->checksum_job) {
                i->checksum_job->on_progress = tar_pull_job_on_progress;

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
