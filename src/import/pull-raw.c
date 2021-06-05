/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <curl/curl.h>
#include <linux/fs.h>
#include <sys/xattr.h>

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
#include "pull-common.h"
#include "pull-job.h"
#include "pull-raw.h"
#include "qcow2-util.h"
#include "rm-rf.h"
#include "string-util.h"
#include "strv.h"
#include "tmpfile-util.h"
#include "utf8.h"
#include "util.h"
#include "web-util.h"

typedef enum RawProgress {
        RAW_DOWNLOADING,
        RAW_VERIFYING,
        RAW_UNPACKING,
        RAW_FINALIZING,
        RAW_COPYING,
} RawProgress;

struct RawPull {
        sd_event *event;
        CurlGlue *glue;

        PullFlags flags;
        ImportVerify verify;
        char *image_root;

        PullJob *raw_job;
        PullJob *checksum_job;
        PullJob *signature_job;
        PullJob *settings_job;
        PullJob *roothash_job;
        PullJob *roothash_signature_job;
        PullJob *verity_job;

        RawPullFinished on_finished;
        void *userdata;

        char *local;

        char *final_path;
        char *temp_path;

        char *settings_path;
        char *settings_temp_path;

        char *roothash_path;
        char *roothash_temp_path;

        char *roothash_signature_path;
        char *roothash_signature_temp_path;

        char *verity_path;
        char *verity_temp_path;
};

RawPull* raw_pull_unref(RawPull *i) {
        if (!i)
                return NULL;

        pull_job_unref(i->raw_job);
        pull_job_unref(i->checksum_job);
        pull_job_unref(i->signature_job);
        pull_job_unref(i->settings_job);
        pull_job_unref(i->roothash_job);
        pull_job_unref(i->roothash_signature_job);
        pull_job_unref(i->verity_job);

        curl_glue_unref(i->glue);
        sd_event_unref(i->event);

        unlink_and_free(i->temp_path);
        unlink_and_free(i->settings_temp_path);
        unlink_and_free(i->roothash_temp_path);
        unlink_and_free(i->roothash_signature_temp_path);
        unlink_and_free(i->verity_temp_path);

        free(i->final_path);
        free(i->settings_path);
        free(i->roothash_path);
        free(i->roothash_signature_path);
        free(i->verity_path);
        free(i->image_root);
        free(i->local);

        return mfree(i);
}

int raw_pull_new(
                RawPull **ret,
                sd_event *event,
                const char *image_root,
                RawPullFinished on_finished,
                void *userdata) {

        _cleanup_(curl_glue_unrefp) CurlGlue *g = NULL;
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(raw_pull_unrefp) RawPull *i = NULL;
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

        i = new(RawPull, 1);
        if (!i)
                return -ENOMEM;

        *i = (RawPull) {
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

static void raw_pull_report_progress(RawPull *i, RawProgress p) {
        unsigned percent;

        assert(i);

        switch (p) {

        case RAW_DOWNLOADING: {
                unsigned remain = 80;

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

                if (i->roothash_job) {
                        percent += i->roothash_job->progress_percent * 5 / 100;
                        remain -= 5;
                }

                if (i->roothash_signature_job) {
                        percent += i->roothash_signature_job->progress_percent * 5 / 100;
                        remain -= 5;
                }

                if (i->verity_job) {
                        percent += i->verity_job->progress_percent * 10 / 100;
                        remain -= 10;
                }

                if (i->raw_job)
                        percent += i->raw_job->progress_percent * remain / 100;
                break;
        }

        case RAW_VERIFYING:
                percent = 80;
                break;

        case RAW_UNPACKING:
                percent = 85;
                break;

        case RAW_FINALIZING:
                percent = 90;
                break;

        case RAW_COPYING:
                percent = 95;
                break;

        default:
                assert_not_reached("Unknown progress state");
        }

        sd_notifyf(false, "X_IMPORT_PROGRESS=%u", percent);
        log_debug("Combined progress %u%%", percent);
}

static int raw_pull_maybe_convert_qcow2(RawPull *i) {
        _cleanup_close_ int converted_fd = -1;
        _cleanup_free_ char *t = NULL;
        int r;

        assert(i);
        assert(i->raw_job);

        r = qcow2_detect(i->raw_job->disk_fd);
        if (r < 0)
                return log_error_errno(r, "Failed to detect whether this is a QCOW2 image: %m");
        if (r == 0)
                return 0;

        /* This is a QCOW2 image, let's convert it */
        r = tempfn_random(i->final_path, NULL, &t);
        if (r < 0)
                return log_oom();

        converted_fd = open(t, O_RDWR|O_CREAT|O_EXCL|O_NOCTTY|O_CLOEXEC, 0664);
        if (converted_fd < 0)
                return log_error_errno(errno, "Failed to create %s: %m", t);

        (void) import_set_nocow_and_log(converted_fd, t);

        log_info("Unpacking QCOW2 file.");

        r = qcow2_convert(i->raw_job->disk_fd, converted_fd);
        if (r < 0) {
                (void) unlink(t);
                return log_error_errno(r, "Failed to convert qcow2 image: %m");
        }

        (void) unlink(i->temp_path);
        free_and_replace(i->temp_path, t);
        CLOSE_AND_REPLACE(i->raw_job->disk_fd, converted_fd);

        return 1;
}

static int raw_pull_determine_path(RawPull *i, const char *suffix, char **field) {
        int r;

        assert(i);
        assert(field);

        if (*field)
                return 0;

        assert(i->raw_job);

        r = pull_make_path(i->raw_job->url, i->raw_job->etag, i->image_root, ".raw-", suffix, field);
        if (r < 0)
                return log_oom();

        return 1;
}

static int raw_pull_copy_auxiliary_file(
                RawPull *i,
                const char *suffix,
                char **path) {

        const char *local;
        int r;

        assert(i);
        assert(suffix);
        assert(path);

        r = raw_pull_determine_path(i, suffix, path);
        if (r < 0)
                return r;

        local = strjoina(i->image_root, "/", i->local, suffix);

        r = copy_file_atomic(*path, local, 0644, 0, 0, COPY_REFLINK | (FLAGS_SET(i->flags, PULL_FORCE) ? COPY_REPLACE : 0));
        if (r == -EEXIST)
                log_warning_errno(r, "File %s already exists, not replacing.", local);
        else if (r == -ENOENT)
                log_debug_errno(r, "Skipping creation of auxiliary file, since none was found.");
        else if (r < 0)
                log_warning_errno(r, "Failed to copy file %s, ignoring: %m", local);
        else
                log_info("Created new file %s.", local);

        return 0;
}

static int raw_pull_make_local_copy(RawPull *i) {
        _cleanup_free_ char *tp = NULL;
        _cleanup_close_ int dfd = -1;
        const char *p;
        int r;

        assert(i);
        assert(i->raw_job);

        if (!i->local)
                return 0;

        if (i->raw_job->etag_exists) {
                /* We have downloaded this one previously, reopen it */

                assert(i->raw_job->disk_fd < 0);

                i->raw_job->disk_fd = open(i->final_path, O_RDONLY|O_NOCTTY|O_CLOEXEC);
                if (i->raw_job->disk_fd < 0)
                        return log_error_errno(errno, "Failed to open vendor image: %m");
        } else {
                /* We freshly downloaded the image, use it */

                assert(i->raw_job->disk_fd >= 0);

                if (lseek(i->raw_job->disk_fd, SEEK_SET, 0) == (off_t) -1)
                        return log_error_errno(errno, "Failed to seek to beginning of vendor image: %m");
        }

        p = strjoina(i->image_root, "/", i->local, ".raw");

        if (FLAGS_SET(i->flags, PULL_FORCE))
                (void) rm_rf(p, REMOVE_ROOT|REMOVE_PHYSICAL|REMOVE_SUBVOLUME);

        r = tempfn_random(p, NULL, &tp);
        if (r < 0)
                return log_oom();

        dfd = open(tp, O_WRONLY|O_CREAT|O_EXCL|O_NOCTTY|O_CLOEXEC, 0664);
        if (dfd < 0)
                return log_error_errno(errno, "Failed to create writable copy of image: %m");

        /* Turn off COW writing. This should greatly improve performance on COW file systems like btrfs,
         * since it reduces fragmentation caused by not allowing in-place writes. */
        (void) import_set_nocow_and_log(dfd, tp);

        r = copy_bytes(i->raw_job->disk_fd, dfd, UINT64_MAX, COPY_REFLINK);
        if (r < 0) {
                (void) unlink(tp);
                return log_error_errno(r, "Failed to make writable copy of image: %m");
        }

        (void) copy_times(i->raw_job->disk_fd, dfd, COPY_CRTIME);
        (void) copy_xattr(i->raw_job->disk_fd, dfd);

        dfd = safe_close(dfd);

        r = rename(tp, p);
        if (r < 0)  {
                r = log_error_errno(errno, "Failed to move writable image into place: %m");
                (void) unlink(tp);
                return r;
        }

        log_info("Created new local image '%s'.", i->local);

        if (FLAGS_SET(i->flags, PULL_SETTINGS)) {
                r = raw_pull_copy_auxiliary_file(i, ".nspawn", &i->settings_path);
                if (r < 0)
                        return r;
        }

        if (FLAGS_SET(i->flags, PULL_ROOTHASH)) {
                r = raw_pull_copy_auxiliary_file(i, ".roothash", &i->roothash_path);
                if (r < 0)
                        return r;
        }

        if (FLAGS_SET(i->flags, PULL_ROOTHASH_SIGNATURE)) {
                r = raw_pull_copy_auxiliary_file(i, ".roothash.p7s", &i->roothash_signature_path);
                if (r < 0)
                        return r;
        }

        if (FLAGS_SET(i->flags, PULL_VERITY)) {
                r = raw_pull_copy_auxiliary_file(i, ".verity", &i->verity_path);
                if (r < 0)
                        return r;
        }

        return 0;
}

static bool raw_pull_is_done(RawPull *i) {
        assert(i);
        assert(i->raw_job);

        if (!PULL_JOB_IS_COMPLETE(i->raw_job))
                return false;
        if (i->checksum_job && !PULL_JOB_IS_COMPLETE(i->checksum_job))
                return false;
        if (i->signature_job && !PULL_JOB_IS_COMPLETE(i->signature_job))
                return false;
        if (i->settings_job && !PULL_JOB_IS_COMPLETE(i->settings_job))
                return false;
        if (i->roothash_job && !PULL_JOB_IS_COMPLETE(i->roothash_job))
                return false;
        if (i->roothash_signature_job && !PULL_JOB_IS_COMPLETE(i->roothash_signature_job))
                return false;
        if (i->verity_job && !PULL_JOB_IS_COMPLETE(i->verity_job))
                return false;

        return true;
}

static int raw_pull_rename_auxiliary_file(
                RawPull *i,
                const char *suffix,
                char **temp_path,
                char **path) {

        int r;

        assert(i);
        assert(temp_path);
        assert(suffix);
        assert(path);

        /* Regenerate final name for this auxiliary file, we might know the etag of the file now, and we should
         * incorporate it in the file name if we can */
        *path = mfree(*path);
        r = raw_pull_determine_path(i, suffix, path);
        if (r < 0)
                return r;

        r = import_make_read_only(*temp_path);
        if (r < 0)
                return r;

        r = rename_noreplace(AT_FDCWD, *temp_path, AT_FDCWD, *path);
        if (r < 0)
                return log_error_errno(r, "Failed to rename file %s to %s: %m", *temp_path, *path);

        *temp_path = mfree(*temp_path);

        return 1;
}

static void raw_pull_job_on_finished(PullJob *j) {
        RawPull *i;
        int r;

        assert(j);
        assert(j->userdata);

        i = j->userdata;
        if (j == i->settings_job) {
                if (j->error != 0)
                        log_info_errno(j->error, "Settings file could not be retrieved, proceeding without.");
        } else if (j == i->roothash_job) {
                if (j->error != 0)
                        log_info_errno(j->error, "Root hash file could not be retrieved, proceeding without.");
        } else if (j == i->roothash_signature_job) {
                if (j->error != 0)
                        log_info_errno(j->error, "Root hash signature file could not be retrieved, proceeding without.");
        } else if (j == i->verity_job) {
                if (j->error != 0)
                        log_info_errno(j->error, "Verity integrity file could not be retrieved, proceeding without. %s", j->url);
        } else if (j->error != 0 && j != i->signature_job) {
                if (j == i->checksum_job)
                        log_error_errno(j->error, "Failed to retrieve SHA256 checksum, cannot verify. (Try --verify=no?)");
                else
                        log_error_errno(j->error, "Failed to retrieve image file. (Wrong URL?)");

                r = j->error;
                goto finish;
        }

        /* This is invoked if either the download completed successfully, or the download was skipped because
         * we already have the etag. In this case ->etag_exists is true.
         *
         * We only do something when we got all three files */

        if (!raw_pull_is_done(i))
                return;

        if (i->signature_job && i->signature_job->error != 0) {
                VerificationStyle style;

                r = verification_style_from_url(i->checksum_job->url, &style);
                if (r < 0) {
                        log_error_errno(r, "Failed to determine verification style from checksum URL: %m");
                        goto finish;
                }

                if (style == VERIFICATION_PER_DIRECTORY) { /* A failed signature file download only matters
                                                            * in per-directory verification mode, since only
                                                            * then the signature is detached, and thus a file
                                                            * of its own. */
                        log_error_errno(j->error, "Failed to retrieve signature file, cannot verify. (Try --verify=no?)");
                        r = i->signature_job->error;
                        goto finish;
                }
        }

        if (i->settings_job)
                i->settings_job->disk_fd = safe_close(i->settings_job->disk_fd);
        if (i->roothash_job)
                i->roothash_job->disk_fd = safe_close(i->roothash_job->disk_fd);
        if (i->roothash_signature_job)
                i->roothash_signature_job->disk_fd = safe_close(i->roothash_signature_job->disk_fd);
        if (i->verity_job)
                i->verity_job->disk_fd = safe_close(i->verity_job->disk_fd);

        r = raw_pull_determine_path(i, ".raw", &i->final_path);
        if (r < 0)
                goto finish;

        if (!i->raw_job->etag_exists) {
                /* This is a new download, verify it, and move it into place */
                assert(i->raw_job->disk_fd >= 0);

                raw_pull_report_progress(i, RAW_VERIFYING);

                r = pull_verify(i->verify,
                                i->raw_job,
                                i->checksum_job,
                                i->signature_job,
                                i->settings_job,
                                i->roothash_job,
                                i->roothash_signature_job,
                                i->verity_job);
                if (r < 0)
                        goto finish;

                raw_pull_report_progress(i, RAW_UNPACKING);

                r = raw_pull_maybe_convert_qcow2(i);
                if (r < 0)
                        goto finish;

                raw_pull_report_progress(i, RAW_FINALIZING);

                if (i->raw_job->etag) {
                        /* Only make a read-only copy if ETag header is set. */
                        r = import_make_read_only_fd(i->raw_job->disk_fd);
                        if (r < 0)
                                goto finish;

                        r = rename_noreplace(AT_FDCWD, i->temp_path, AT_FDCWD, i->final_path);
                        if (r < 0) {
                                log_error_errno(r, "Failed to rename raw file to %s: %m", i->final_path);
                                goto finish;
                        }
                }

                i->temp_path = mfree(i->temp_path);

                if (i->roothash_job &&
                    i->roothash_job->error == 0) {
                        r = raw_pull_rename_auxiliary_file(i, ".roothash", &i->roothash_temp_path, &i->roothash_path);
                        if (r < 0)
                                goto finish;
                }

                if (i->settings_job &&
                    i->settings_job->error == 0) {
                        r = raw_pull_rename_auxiliary_file(i, ".nspawn", &i->settings_temp_path, &i->settings_path);
                        if (r < 0)
                                goto finish;
                }
        }

        raw_pull_report_progress(i, RAW_COPYING);

        r = raw_pull_make_local_copy(i);
        if (r < 0)
                goto finish;

        r = 0;

finish:
        if (i->on_finished)
                i->on_finished(i, r, i->userdata);
        else
                sd_event_exit(i->event, r);
}

static int raw_pull_job_on_open_disk_generic(
                RawPull *i,
                PullJob *j,
                const char *extra,
                char **temp_path) {

        int r;

        assert(i);
        assert(j);
        assert(extra);
        assert(temp_path);

        if (!*temp_path) {
                r = tempfn_random_child(i->image_root, extra, temp_path);
                if (r < 0)
                        return log_oom();
        }

        (void) mkdir_parents_label(*temp_path, 0700);

        j->disk_fd = open(*temp_path, O_RDWR|O_CREAT|O_EXCL|O_NOCTTY|O_CLOEXEC, 0664);
        if (j->disk_fd < 0)
                return log_error_errno(errno, "Failed to create %s: %m", *temp_path);

        return 0;
}

static int raw_pull_job_on_open_disk_raw(PullJob *j) {
        RawPull *i;
        int r;

        assert(j);
        assert(j->userdata);

        i = j->userdata;
        assert(i->raw_job == j);

        r = raw_pull_job_on_open_disk_generic(i, j, "raw", &i->temp_path);
        if (r < 0)
                return r;

        (void) import_set_nocow_and_log(j->disk_fd, i->temp_path);
        return 0;
}

static int raw_pull_job_on_open_disk_settings(PullJob *j) {
        RawPull *i;

        assert(j);
        assert(j->userdata);

        i = j->userdata;
        assert(i->settings_job == j);

        return raw_pull_job_on_open_disk_generic(i, j, "settings", &i->settings_temp_path);
}

static int raw_pull_job_on_open_disk_roothash(PullJob *j) {
        RawPull *i;

        assert(j);
        assert(j->userdata);

        i = j->userdata;
        assert(i->roothash_job == j);

        return raw_pull_job_on_open_disk_generic(i, j, "roothash", &i->roothash_temp_path);
}

static int raw_pull_job_on_open_disk_roothash_signature(PullJob *j) {
        RawPull *i;

        assert(j);
        assert(j->userdata);

        i = j->userdata;
        assert(i->roothash_signature_job == j);

        return raw_pull_job_on_open_disk_generic(i, j, "roothash.p7s", &i->roothash_signature_temp_path);
}

static int raw_pull_job_on_open_disk_verity(PullJob *j) {
        RawPull *i;

        assert(j);
        assert(j->userdata);

        i = j->userdata;
        assert(i->verity_job == j);

        return raw_pull_job_on_open_disk_generic(i, j, "verity", &i->verity_temp_path);
}

static void raw_pull_job_on_progress(PullJob *j) {
        RawPull *i;

        assert(j);
        assert(j->userdata);

        i = j->userdata;

        raw_pull_report_progress(i, RAW_DOWNLOADING);
}

int raw_pull_start(
                RawPull *i,
                const char *url,
                const char *local,
                PullFlags flags,
                ImportVerify verify) {

        int r;

        assert(i);
        assert(verify < _IMPORT_VERIFY_MAX);
        assert(verify >= 0);
        assert(!(flags & ~PULL_FLAGS_MASK_RAW));

        if (!http_url_is_valid(url))
                return -EINVAL;

        if (local && !hostname_is_valid(local, 0))
                return -EINVAL;

        if (i->raw_job)
                return -EBUSY;

        r = free_and_strdup(&i->local, local);
        if (r < 0)
                return r;

        i->flags = flags;
        i->verify = verify;

        /* Queue job for the image itself */
        r = pull_job_new(&i->raw_job, url, i->glue, i);
        if (r < 0)
                return r;

        i->raw_job->on_finished = raw_pull_job_on_finished;
        i->raw_job->on_open_disk = raw_pull_job_on_open_disk_raw;
        i->raw_job->on_progress = raw_pull_job_on_progress;
        i->raw_job->calc_checksum = verify != IMPORT_VERIFY_NO;

        r = pull_find_old_etags(url, i->image_root, DT_REG, ".raw-", ".raw", &i->raw_job->old_etags);
        if (r < 0)
                return r;

        r = pull_make_verification_jobs(&i->checksum_job, &i->signature_job, verify, url, i->glue, raw_pull_job_on_finished, i);
        if (r < 0)
                return r;

        if (FLAGS_SET(flags, PULL_SETTINGS)) {
                r = pull_make_auxiliary_job(&i->settings_job, url, raw_strip_suffixes, ".nspawn", i->glue, raw_pull_job_on_finished, i);
                if (r < 0)
                        return r;

                i->settings_job->on_open_disk = raw_pull_job_on_open_disk_settings;
                i->settings_job->on_progress = raw_pull_job_on_progress;
                i->settings_job->calc_checksum = verify != IMPORT_VERIFY_NO;
        }

        if (FLAGS_SET(flags, PULL_ROOTHASH)) {
                r = pull_make_auxiliary_job(&i->roothash_job, url, raw_strip_suffixes, ".roothash", i->glue, raw_pull_job_on_finished, i);
                if (r < 0)
                        return r;

                i->roothash_job->on_open_disk = raw_pull_job_on_open_disk_roothash;
                i->roothash_job->on_progress = raw_pull_job_on_progress;
                i->roothash_job->calc_checksum = verify != IMPORT_VERIFY_NO;
        }

        if (FLAGS_SET(flags, PULL_ROOTHASH_SIGNATURE)) {
                r = pull_make_auxiliary_job(&i->roothash_signature_job, url, raw_strip_suffixes, ".roothash.p7s", i->glue, raw_pull_job_on_finished, i);
                if (r < 0)
                        return r;

                i->roothash_signature_job->on_open_disk = raw_pull_job_on_open_disk_roothash_signature;
                i->roothash_signature_job->on_progress = raw_pull_job_on_progress;
                i->roothash_signature_job->calc_checksum = verify != IMPORT_VERIFY_NO;
        }

        if (FLAGS_SET(flags, PULL_VERITY)) {
                r = pull_make_auxiliary_job(&i->verity_job, url, raw_strip_suffixes, ".verity", i->glue, raw_pull_job_on_finished, i);
                if (r < 0)
                        return r;

                i->verity_job->on_open_disk = raw_pull_job_on_open_disk_verity;
                i->verity_job->on_progress = raw_pull_job_on_progress;
                i->verity_job->calc_checksum = verify != IMPORT_VERIFY_NO;
        }

        r = pull_job_begin(i->raw_job);
        if (r < 0)
                return r;

        if (i->checksum_job) {
                i->checksum_job->on_progress = raw_pull_job_on_progress;
                i->checksum_job->on_not_found = pull_job_restart_with_sha256sum;

                r = pull_job_begin(i->checksum_job);
                if (r < 0)
                        return r;
        }

        if (i->signature_job) {
                i->signature_job->on_progress = raw_pull_job_on_progress;

                r = pull_job_begin(i->signature_job);
                if (r < 0)
                        return r;
        }

        if (i->settings_job) {
                r = pull_job_begin(i->settings_job);
                if (r < 0)
                        return r;
        }

        if (i->roothash_job) {
                r = pull_job_begin(i->roothash_job);
                if (r < 0)
                        return r;
        }

        if (i->roothash_signature_job) {
                r = pull_job_begin(i->roothash_signature_job);
                if (r < 0)
                        return r;
        }

        if (i->verity_job) {
                r = pull_job_begin(i->verity_job);
                if (r < 0)
                        return r;
        }

        return 0;
}
