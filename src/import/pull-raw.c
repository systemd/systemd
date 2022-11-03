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
#include "install-file.h"
#include "macro.h"
#include "mkdir-label.h"
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

        uint64_t offset;

        PullJob *raw_job;
        PullJob *checksum_job;
        PullJob *signature_job;
        PullJob *settings_job;
        PullJob *roothash_job;
        PullJob *roothash_signature_job;
        PullJob *verity_job;

        RawPullFinished on_finished;
        void *userdata;

        char *local; /* In PULL_DIRECT mode the path we are supposed to place things in, otherwise the
                      * machine name of the final copy we make */

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

        char *checksum;
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
        free(i->checksum);

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
                .offset = UINT64_MAX,
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
                assert_not_reached();
        }

        sd_notifyf(false, "X_IMPORT_PROGRESS=%u", percent);
        log_debug("Combined progress %u%%", percent);
}

static int raw_pull_maybe_convert_qcow2(RawPull *i) {
        _cleanup_(unlink_and_freep) char *t = NULL;
        _cleanup_close_ int converted_fd = -1;
        _cleanup_free_ char *f = NULL;
        int r;

        assert(i);
        assert(i->raw_job);
        assert(!FLAGS_SET(i->flags, PULL_DIRECT));

        if (!FLAGS_SET(i->flags, PULL_CONVERT_QCOW2))
                return 0;

        assert(i->final_path);
        assert(i->raw_job->close_disk_fd);

        r = qcow2_detect(i->raw_job->disk_fd);
        if (r < 0)
                return log_error_errno(r, "Failed to detect whether this is a QCOW2 image: %m");
        if (r == 0)
                return 0;

        /* This is a QCOW2 image, let's convert it */
        r = tempfn_random(i->final_path, NULL, &f);
        if (r < 0)
                return log_oom();

        converted_fd = open(f, O_RDWR|O_CREAT|O_EXCL|O_NOCTTY|O_CLOEXEC, 0664);
        if (converted_fd < 0)
                return log_error_errno(errno, "Failed to create %s: %m", f);

        t = TAKE_PTR(f);

        (void) import_set_nocow_and_log(converted_fd, t);

        log_info("Unpacking QCOW2 file.");

        r = qcow2_convert(i->raw_job->disk_fd, converted_fd);
        if (r < 0)
                return log_error_errno(r, "Failed to convert qcow2 image: %m");

        unlink_and_free(i->temp_path);
        i->temp_path = TAKE_PTR(t);
        close_and_replace(i->raw_job->disk_fd, converted_fd);

        return 1;
}

static int raw_pull_determine_path(
                RawPull *i,
                const char *suffix,
                char **field /* input + output (!) */) {
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
                char **path /* input + output (!) */) {

        const char *local;
        int r;

        assert(i);
        assert(suffix);
        assert(path);

        r = raw_pull_determine_path(i, suffix, path);
        if (r < 0)
                return r;

        local = strjoina(i->image_root, "/", i->local, suffix);

        r = copy_file_atomic(
                        *path,
                        local,
                        0644,
                        0, 0,
                        COPY_REFLINK |
                        (FLAGS_SET(i->flags, PULL_FORCE) ? COPY_REPLACE : 0) |
                        (FLAGS_SET(i->flags, PULL_SYNC) ? COPY_FSYNC_FULL : 0));
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
        _cleanup_(unlink_and_freep) char *tp = NULL;
        _cleanup_free_ char *f = NULL;
        _cleanup_close_ int dfd = -1;
        const char *p;
        int r;

        assert(i);
        assert(i->raw_job);
        assert(!FLAGS_SET(i->flags, PULL_DIRECT));

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
                assert(i->offset == UINT64_MAX);

                if (lseek(i->raw_job->disk_fd, SEEK_SET, 0) == (off_t) -1)
                        return log_error_errno(errno, "Failed to seek to beginning of vendor image: %m");
        }

        p = strjoina(i->image_root, "/", i->local, ".raw");

        r = tempfn_random(p, NULL, &f);
        if (r < 0)
                return log_oom();

        dfd = open(f, O_WRONLY|O_CREAT|O_EXCL|O_NOCTTY|O_CLOEXEC, 0664);
        if (dfd < 0)
                return log_error_errno(errno, "Failed to create writable copy of image: %m");

        tp = TAKE_PTR(f);

        /* Turn off COW writing. This should greatly improve performance on COW file systems like btrfs,
         * since it reduces fragmentation caused by not allowing in-place writes. */
        (void) import_set_nocow_and_log(dfd, tp);

        r = copy_bytes(i->raw_job->disk_fd, dfd, UINT64_MAX, COPY_REFLINK);
        if (r < 0)
                return log_error_errno(r, "Failed to make writable copy of image: %m");

        (void) copy_times(i->raw_job->disk_fd, dfd, COPY_CRTIME);
        (void) copy_xattr(i->raw_job->disk_fd, dfd, 0);

        dfd = safe_close(dfd);

        r = install_file(AT_FDCWD, tp,
                         AT_FDCWD, p,
                         (i->flags & PULL_FORCE ? INSTALL_REPLACE : 0) |
                         (i->flags & PULL_READ_ONLY ? INSTALL_READ_ONLY : 0) |
                         (i->flags & PULL_SYNC ? INSTALL_FSYNC_FULL : 0));
        if (r < 0)
                return log_error_errno(errno, "Failed to move local image into place '%s': %m", p);

        tp = mfree(tp);

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
        assert(path);
        assert(temp_path);
        assert(*temp_path);
        assert(suffix);

        /* Regenerate final name for this auxiliary file, we might know the etag of the file now, and we should
         * incorporate it in the file name if we can */
        *path = mfree(*path);
        r = raw_pull_determine_path(i, suffix, path);
        if (r < 0)
                return r;

        r = install_file(
                        AT_FDCWD, *temp_path,
                        AT_FDCWD, *path,
                        INSTALL_READ_ONLY|
                        (i->flags & PULL_SYNC ? INSTALL_FSYNC_FULL : 0));
        if (r < 0)
                return log_error_errno(r, "Failed to move '%s' into place: %m", *path);

        *temp_path = mfree(*temp_path);
        return 1;
}

static void raw_pull_job_on_finished(PullJob *j) {
        RawPull *i;
        PullJob *jj;
        int r;

        assert(j);
        assert(j->userdata);

        i = j->userdata;

        if (j->error != 0) {
                /* Only the main job and the checksum job are fatal if they fail. The other fails are just
                 * "decoration", that we'll download if we can. The signature job isn't fatal here because we
                 * might not actually need it in case Suse style signatures are used, that are inline in the
                 * checksum file. */

                if (j == i->raw_job) {
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
                else if (j == i->roothash_job)
                        log_info_errno(j->error, "Root hash file could not be retrieved, proceeding without.");
                else if (j == i->roothash_signature_job)
                        log_info_errno(j->error, "Root hash signature file could not be retrieved, proceeding without.");
                else if (j == i->verity_job)
                        log_info_errno(j->error, "Verity integrity file could not be retrieved, proceeding without.");
                else
                        assert_not_reached();
        }

        /* This is invoked if either the download completed successfully, or the download was skipped because
         * we already have the etag. In this case ->etag_exists is true.
         *
         * We only do something when we got all files */

        if (!raw_pull_is_done(i))
                return;

        if (i->signature_job && i->signature_job->error != 0) {
                VerificationStyle style;
                PullJob *verify_job;

                /* The signature job failed. Let's see if we actually need it */

                verify_job = i->checksum_job ?: i->raw_job; /* if the checksum job doesn't exist this must be
                                                             * because the main job is the checksum file
                                                             * itself */

                assert(verify_job);

                r = verification_style_from_url(verify_job->url, &style);
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

        /* Let's close these auxiliary files now, we don't need access to them anymore. */
        FOREACH_POINTER(jj, i->settings_job, i->roothash_job, i->roothash_signature_job, i->verity_job)
                pull_job_close_disk_fd(jj);

        if (!i->raw_job->etag_exists) {
                raw_pull_report_progress(i, RAW_VERIFYING);

                r = pull_verify(i->verify,
                                i->checksum,
                                i->raw_job,
                                i->checksum_job,
                                i->signature_job,
                                i->settings_job,
                                i->roothash_job,
                                i->roothash_signature_job,
                                i->verity_job);
                if (r < 0)
                        goto finish;
        }

        if (i->flags & PULL_DIRECT) {
                assert(!i->settings_job);
                assert(!i->roothash_job);
                assert(!i->roothash_signature_job);
                assert(!i->verity_job);

                raw_pull_report_progress(i, RAW_FINALIZING);

                if (i->local) {
                        r = install_file(AT_FDCWD, i->local,
                                         AT_FDCWD, NULL,
                                         ((i->flags & PULL_READ_ONLY) && i->offset == UINT64_MAX ? INSTALL_READ_ONLY : 0) |
                                         (i->flags & PULL_SYNC ? INSTALL_FSYNC_FULL : 0));
                        if (r < 0) {
                                log_error_errno(r, "Failed to finalize raw file to '%s': %m", i->local);
                                goto finish;
                        }
                }
        } else {
                r = raw_pull_determine_path(i, ".raw", &i->final_path);
                if (r < 0)
                        goto finish;

                if (!i->raw_job->etag_exists) {
                        /* This is a new download, verify it, and move it into place */

                        assert(i->temp_path);
                        assert(i->final_path);

                        raw_pull_report_progress(i, RAW_UNPACKING);

                        r = raw_pull_maybe_convert_qcow2(i);
                        if (r < 0)
                                goto finish;

                        raw_pull_report_progress(i, RAW_FINALIZING);

                        r = install_file(AT_FDCWD, i->temp_path,
                                         AT_FDCWD, i->final_path,
                                         INSTALL_READ_ONLY|
                                         (i->flags & PULL_SYNC ? INSTALL_FSYNC_FULL : 0));
                        if (r < 0) {
                                log_error_errno(r, "Failed to move raw file to '%s': %m", i->final_path);
                                goto finish;
                        }

                        i->temp_path = mfree(i->temp_path);

                        if (i->settings_job &&
                            i->settings_job->error == 0) {
                                r = raw_pull_rename_auxiliary_file(i, ".nspawn", &i->settings_temp_path, &i->settings_path);
                                if (r < 0)
                                        goto finish;
                        }

                        if (i->roothash_job &&
                            i->roothash_job->error == 0) {
                                r = raw_pull_rename_auxiliary_file(i, ".roothash", &i->roothash_temp_path, &i->roothash_path);
                                if (r < 0)
                                        goto finish;
                        }

                        if (i->roothash_signature_job &&
                            i->roothash_signature_job->error == 0) {
                                r = raw_pull_rename_auxiliary_file(i, ".roothash.p7s", &i->roothash_signature_temp_path, &i->roothash_signature_path);
                                if (r < 0)
                                        goto finish;
                        }

                        if (i->verity_job &&
                            i->verity_job->error == 0) {
                                r = raw_pull_rename_auxiliary_file(i, ".verity", &i->verity_temp_path, &i->verity_path);
                                if (r < 0)
                                        goto finish;
                        }
                }

                raw_pull_report_progress(i, RAW_COPYING);

                r = raw_pull_make_local_copy(i);
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

static int raw_pull_job_on_open_disk_generic(
                RawPull *i,
                PullJob *j,
                const char *extra,
                char **temp_path /* input + output */) {

        int r;

        assert(i);
        assert(j);
        assert(extra);
        assert(temp_path);

        assert(!FLAGS_SET(i->flags, PULL_DIRECT));

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
        assert(j->disk_fd < 0);

        if (i->flags & PULL_DIRECT) {

                if (!i->local) { /* If no local name specified, the pull job will write its data to stdout */
                        j->disk_fd = STDOUT_FILENO;
                        j->close_disk_fd = false;
                        return 0;
                }

                (void) mkdir_parents_label(i->local, 0700);

                j->disk_fd = open(i->local, O_RDWR|O_NOCTTY|O_CLOEXEC|(i->offset == UINT64_MAX ? O_TRUNC|O_CREAT : 0), 0664);
                if (j->disk_fd < 0)
                        return log_error_errno(errno, "Failed to open destination '%s': %m", i->local);

                if (i->offset == UINT64_MAX)
                        (void) import_set_nocow_and_log(j->disk_fd, i->local);

        } else {
                r = raw_pull_job_on_open_disk_generic(i, j, "raw", &i->temp_path);
                if (r < 0)
                        return r;

                assert(i->offset == UINT64_MAX);
                (void) import_set_nocow_and_log(j->disk_fd, i->temp_path);
        }

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
                uint64_t offset,
                uint64_t size_max,
                PullFlags flags,
                ImportVerify verify,
                const char *checksum) {

        PullJob *j;
        int r;

        assert(i);
        assert(url);
        assert(verify == _IMPORT_VERIFY_INVALID || verify < _IMPORT_VERIFY_MAX);
        assert(verify == _IMPORT_VERIFY_INVALID || verify >= 0);
        assert((verify < 0) || !checksum);
        assert(!(flags & ~PULL_FLAGS_MASK_RAW));
        assert(offset == UINT64_MAX || FLAGS_SET(flags, PULL_DIRECT));
        assert(!(flags & (PULL_SETTINGS|PULL_ROOTHASH|PULL_ROOTHASH_SIGNATURE|PULL_VERITY)) || !(flags & PULL_DIRECT));
        assert(!(flags & (PULL_SETTINGS|PULL_ROOTHASH|PULL_ROOTHASH_SIGNATURE|PULL_VERITY)) || !checksum);

        if (!http_url_is_valid(url) && !file_url_is_valid(url))
                return -EINVAL;

        if (local && !pull_validate_local(local, flags))
                return -EINVAL;

        if (i->raw_job)
                return -EBUSY;

        r = free_and_strdup(&i->local, local);
        if (r < 0)
                return r;

        r = free_and_strdup(&i->checksum, checksum);
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

        if (checksum)
                i->raw_job->calc_checksum = true;
        else if (verify != IMPORT_VERIFY_NO) {
                /* Calculate checksum of the main download unless the users asks for a SHA256SUM file or its
                 * signature, which we let gpg verify instead. */

                r = pull_url_needs_checksum(url);
                if (r < 0)
                        return r;

                i->raw_job->calc_checksum = r;
                i->raw_job->force_memory = true; /* make sure this is both written to disk if that's
                                                  * requested and into memory, since we need to verify it */
        }

        if (size_max != UINT64_MAX)
                i->raw_job->uncompressed_max = size_max;
        if (offset != UINT64_MAX)
                i->raw_job->offset = i->offset = offset;

        if (!FLAGS_SET(flags, PULL_DIRECT)) {
                r = pull_find_old_etags(url, i->image_root, DT_REG, ".raw-", ".raw", &i->raw_job->old_etags);
                if (r < 0)
                        return r;
        }

        r = pull_make_verification_jobs(
                        &i->checksum_job,
                        &i->signature_job,
                        verify,
                        i->checksum,
                        url,
                        i->glue,
                        raw_pull_job_on_finished,
                        i);
        if (r < 0)
                return r;

        if (FLAGS_SET(flags, PULL_SETTINGS)) {
                r = pull_make_auxiliary_job(
                                &i->settings_job,
                                url,
                                raw_strip_suffixes,
                                ".nspawn",
                                verify,
                                i->glue,
                                raw_pull_job_on_open_disk_settings,
                                raw_pull_job_on_finished,
                                i);
                if (r < 0)
                        return r;
        }

        if (FLAGS_SET(flags, PULL_ROOTHASH)) {
                r = pull_make_auxiliary_job(
                                &i->roothash_job,
                                url,
                                raw_strip_suffixes,
                                ".roothash",
                                verify,
                                i->glue,
                                raw_pull_job_on_open_disk_roothash,
                                raw_pull_job_on_finished,
                                i);
                if (r < 0)
                        return r;
        }

        if (FLAGS_SET(flags, PULL_ROOTHASH_SIGNATURE)) {
                r = pull_make_auxiliary_job(
                                &i->roothash_signature_job,
                                url,
                                raw_strip_suffixes,
                                ".roothash.p7s",
                                verify,
                                i->glue,
                                raw_pull_job_on_open_disk_roothash_signature,
                                raw_pull_job_on_finished,
                                i);
                if (r < 0)
                        return r;
        }

        if (FLAGS_SET(flags, PULL_VERITY)) {
                r = pull_make_auxiliary_job(
                                &i->verity_job,
                                url,
                                raw_strip_suffixes,
                                ".verity",
                                verify,
                                i->glue,
                                raw_pull_job_on_open_disk_verity,
                                raw_pull_job_on_finished,
                                i);
                if (r < 0)
                        return r;
        }

        FOREACH_POINTER(j,
                        i->raw_job,
                        i->checksum_job,
                        i->signature_job,
                        i->settings_job,
                        i->roothash_job,
                        i->roothash_signature_job,
                        i->verity_job) {

                if (!j)
                        continue;

                j->on_progress = raw_pull_job_on_progress;
                j->sync = FLAGS_SET(flags, PULL_SYNC);

                r = pull_job_begin(j);
                if (r < 0)
                        return r;
        }

        return 0;
}
