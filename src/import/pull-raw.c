/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-daemon.h"
#include "sd-event.h"

#include "alloc-util.h"
#include "copy.h"
#include "curl-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "import-common.h"
#include "import-util.h"
#include "install-file.h"
#include "log.h"
#include "mkdir-label.h"
#include "pull-common.h"
#include "pull-job.h"
#include "pull-raw.h"
#include "qcow2-util.h"
#include "string-util.h"
#include "tmpfile-util.h"
#include "web-util.h"

typedef enum RawProgress {
        RAW_DOWNLOADING,
        RAW_VERIFYING,
        RAW_UNPACKING,
        RAW_FINALIZING,
        RAW_COPYING,
} RawProgress;

typedef struct RawPull {
        sd_event *event;
        CurlGlue *glue;

        ImportFlags flags;
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
                      * image name of the final copy we make */

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
} RawPull;

RawPull* raw_pull_unref(RawPull *p) {
        if (!p)
                return NULL;

        pull_job_unref(p->raw_job);
        pull_job_unref(p->checksum_job);
        pull_job_unref(p->signature_job);
        pull_job_unref(p->settings_job);
        pull_job_unref(p->roothash_job);
        pull_job_unref(p->roothash_signature_job);
        pull_job_unref(p->verity_job);

        curl_glue_unref(p->glue);
        sd_event_unref(p->event);

        unlink_and_free(p->temp_path);
        unlink_and_free(p->settings_temp_path);
        unlink_and_free(p->roothash_temp_path);
        unlink_and_free(p->roothash_signature_temp_path);
        unlink_and_free(p->verity_temp_path);

        free(p->final_path);
        free(p->settings_path);
        free(p->roothash_path);
        free(p->roothash_signature_path);
        free(p->verity_path);
        free(p->image_root);
        free(p->local);

        return mfree(p);
}

int raw_pull_new(
                RawPull **ret,
                sd_event *event,
                const char *image_root,
                RawPullFinished on_finished,
                void *userdata) {

        _cleanup_(curl_glue_unrefp) CurlGlue *g = NULL;
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(raw_pull_unrefp) RawPull *p = NULL;
        _cleanup_free_ char *root = NULL;
        int r;

        assert(ret);
        assert(image_root);

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

        p = new(RawPull, 1);
        if (!p)
                return -ENOMEM;

        *p = (RawPull) {
                .on_finished = on_finished,
                .userdata = userdata,
                .image_root = TAKE_PTR(root),
                .event = TAKE_PTR(e),
                .glue = TAKE_PTR(g),
                .offset = UINT64_MAX,
        };

        p->glue->on_finished = pull_job_curl_on_finished;
        p->glue->userdata = p;

        *ret = TAKE_PTR(p);

        return 0;
}

static void raw_pull_report_progress(RawPull *p, RawProgress progress) {
        unsigned percent;

        assert(p);

        switch (progress) {

        case RAW_DOWNLOADING: {
                unsigned remain = 80;

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

                if (p->roothash_job) {
                        percent += p->roothash_job->progress_percent * 5 / 100;
                        remain -= 5;
                }

                if (p->roothash_signature_job) {
                        percent += p->roothash_signature_job->progress_percent * 5 / 100;
                        remain -= 5;
                }

                if (p->verity_job) {
                        percent += p->verity_job->progress_percent * 10 / 100;
                        remain -= 10;
                }

                if (p->raw_job)
                        percent += p->raw_job->progress_percent * remain / 100;
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

        sd_notifyf(false, "X_IMPORT_PROGRESS=%u%%", percent);
        log_debug("Combined progress %u%%", percent);
}

static int raw_pull_maybe_convert_qcow2(RawPull *p) {
        _cleanup_(unlink_and_freep) char *t = NULL;
        _cleanup_close_ int converted_fd = -EBADF;
        _cleanup_free_ char *f = NULL;
        int r;

        assert(p);
        assert(p->raw_job);
        assert(!FLAGS_SET(p->flags, IMPORT_DIRECT));

        if (!FLAGS_SET(p->flags, IMPORT_CONVERT_QCOW2))
                return 0;

        assert(p->final_path);
        assert(p->raw_job->close_disk_fd);

        r = qcow2_detect(p->raw_job->disk_fd);
        if (r < 0)
                return log_error_errno(r, "Failed to detect whether this is a QCOW2 image: %m");
        if (r == 0)
                return 0;

        /* This is a QCOW2 image, let's convert it */
        r = tempfn_random(p->final_path, NULL, &f);
        if (r < 0)
                return log_oom();

        converted_fd = open(f, O_RDWR|O_CREAT|O_EXCL|O_NOCTTY|O_CLOEXEC, 0664);
        if (converted_fd < 0)
                return log_error_errno(errno, "Failed to create %s: %m", f);

        t = TAKE_PTR(f);

        (void) import_set_nocow_and_log(converted_fd, t);

        log_info("Unpacking QCOW2 file.");

        r = qcow2_convert(p->raw_job->disk_fd, converted_fd);
        if (r < 0)
                return log_error_errno(r, "Failed to convert qcow2 image: %m");

        unlink_and_free(p->temp_path);
        p->temp_path = TAKE_PTR(t);
        close_and_replace(p->raw_job->disk_fd, converted_fd);

        return 1;
}

static int raw_pull_determine_path(
                RawPull *p,
                const char *suffix,
                char **field /* input + output (!) */) {
        int r;

        assert(p);
        assert(field);

        if (*field)
                return 0;

        assert(p->raw_job);

        r = pull_make_path(p->raw_job->url, p->raw_job->etag, p->image_root, ".raw-", suffix, field);
        if (r < 0)
                return log_oom();

        return 1;
}

static int raw_pull_copy_auxiliary_file(
                RawPull *p,
                const char *suffix,
                char **path /* input + output (!) */) {

        _cleanup_free_ char *local = NULL;
        int r;

        assert(p);
        assert(suffix);
        assert(path);

        r = raw_pull_determine_path(p, suffix, path);
        if (r < 0)
                return r;

        local = strjoin(p->image_root, "/", p->local, suffix);
        if (!local)
                return log_oom();

        if (FLAGS_SET(p->flags, IMPORT_PULL_KEEP_DOWNLOAD))
                r = copy_file_atomic(
                                *path,
                                local,
                                0644,
                                COPY_REFLINK |
                                (FLAGS_SET(p->flags, IMPORT_FORCE) ? COPY_REPLACE : 0) |
                                (FLAGS_SET(p->flags, IMPORT_SYNC) ? COPY_FSYNC_FULL : 0));
        else
                r = install_file(AT_FDCWD, *path,
                                 AT_FDCWD, local,
                                 (p->flags & IMPORT_FORCE ? INSTALL_REPLACE : 0) |
                                 (p->flags & IMPORT_SYNC ? INSTALL_SYNCFS : 0));
        if (r == -EEXIST)
                log_warning_errno(r, "File %s already exists, not replacing.", local);
        else if (r == -ENOENT)
                log_debug_errno(r, "Skipping creation of auxiliary file, since none was found.");
        else if (r < 0)
                log_warning_errno(r, "Failed to install file %s, ignoring: %m", local);
        else
                log_info("Created new file %s.", local);

        return 0;
}

static int raw_pull_make_local_copy(RawPull *p) {
        _cleanup_(unlink_and_freep) char *tp = NULL;
        _cleanup_free_ char *path = NULL;
        int r;

        assert(p);
        assert(p->raw_job);
        assert(!FLAGS_SET(p->flags, IMPORT_DIRECT));

        if (!p->local)
                return 0;

        if (p->raw_job->etag_exists) {
                /* We have downloaded this one previously, reopen it */

                assert(p->raw_job->disk_fd < 0);

                p->raw_job->disk_fd = open(p->final_path, O_RDONLY|O_NOCTTY|O_CLOEXEC);
                if (p->raw_job->disk_fd < 0)
                        return log_error_errno(errno, "Failed to open vendor image: %m");
        } else {
                /* We freshly downloaded the image, use it */

                assert(p->raw_job->disk_fd >= 0);
                assert(p->offset == UINT64_MAX);

                if (lseek(p->raw_job->disk_fd, 0, SEEK_SET) < 0)
                        return log_error_errno(errno, "Failed to seek to beginning of vendor image: %m");
        }

        path = strjoin(p->image_root, "/", p->local, ".raw");
        if (!path)
                return log_oom();

        const char *source;
        if (FLAGS_SET(p->flags, IMPORT_PULL_KEEP_DOWNLOAD)) {
                _cleanup_close_ int dfd = -EBADF;
                _cleanup_free_ char *f = NULL;

                r = tempfn_random(path, NULL, &f);
                if (r < 0)
                        return log_oom();

                dfd = open(f, O_WRONLY|O_CREAT|O_EXCL|O_NOCTTY|O_CLOEXEC, 0664);
                if (dfd < 0)
                        return log_error_errno(errno, "Failed to create writable copy of image: %m");

                tp = TAKE_PTR(f);

                /* Turn off COW writing. This should greatly improve performance on COW file systems like btrfs,
                 * since it reduces fragmentation caused by not allowing in-place writes. */
                (void) import_set_nocow_and_log(dfd, tp);

                r = copy_bytes(p->raw_job->disk_fd, dfd, UINT64_MAX, COPY_REFLINK);
                if (r < 0)
                        return log_error_errno(r, "Failed to make writable copy of image: %m");

                (void) copy_times(p->raw_job->disk_fd, dfd, COPY_CRTIME);
                (void) copy_xattr(p->raw_job->disk_fd, NULL, dfd, NULL, 0);

                dfd = safe_close(dfd);

                source = tp;
        } else
                source = p->final_path;

        r = install_file(AT_FDCWD, source,
                         AT_FDCWD, path,
                         (p->flags & IMPORT_FORCE ? INSTALL_REPLACE : 0) |
                         (p->flags & IMPORT_READ_ONLY ? INSTALL_READ_ONLY : 0) |
                         (p->flags & IMPORT_SYNC ? INSTALL_FSYNC_FULL : 0));
        if (r < 0)
                return log_error_errno(r, "Failed to move local image into place '%s': %m", path);

        tp = mfree(tp);

        log_info("Created new local image '%s'.", p->local);

        if (FLAGS_SET(p->flags, IMPORT_PULL_SETTINGS)) {
                r = raw_pull_copy_auxiliary_file(p, ".nspawn", &p->settings_path);
                if (r < 0)
                        return r;
        }

        if (FLAGS_SET(p->flags, IMPORT_PULL_ROOTHASH)) {
                r = raw_pull_copy_auxiliary_file(p, ".roothash", &p->roothash_path);
                if (r < 0)
                        return r;
        }

        if (FLAGS_SET(p->flags, IMPORT_PULL_ROOTHASH_SIGNATURE)) {
                r = raw_pull_copy_auxiliary_file(p, ".roothash.p7s", &p->roothash_signature_path);
                if (r < 0)
                        return r;
        }

        if (FLAGS_SET(p->flags, IMPORT_PULL_VERITY)) {
                r = raw_pull_copy_auxiliary_file(p, ".verity", &p->verity_path);
                if (r < 0)
                        return r;
        }

        return 0;
}

static bool raw_pull_is_done(RawPull *p) {
        assert(p);
        assert(p->raw_job);

        if (!PULL_JOB_IS_COMPLETE(p->raw_job))
                return false;
        if (p->checksum_job && !PULL_JOB_IS_COMPLETE(p->checksum_job))
                return false;
        if (p->signature_job && !PULL_JOB_IS_COMPLETE(p->signature_job))
                return false;
        if (p->settings_job && !PULL_JOB_IS_COMPLETE(p->settings_job))
                return false;
        if (p->roothash_job && !PULL_JOB_IS_COMPLETE(p->roothash_job))
                return false;
        if (p->roothash_signature_job && !PULL_JOB_IS_COMPLETE(p->roothash_signature_job))
                return false;
        if (p->verity_job && !PULL_JOB_IS_COMPLETE(p->verity_job))
                return false;

        return true;
}

static int raw_pull_rename_auxiliary_file(
                RawPull *p,
                const char *suffix,
                char **temp_path,
                char **path) {

        int r;

        assert(p);
        assert(path);
        assert(temp_path);
        assert(*temp_path);
        assert(suffix);

        /* Regenerate final name for this auxiliary file, we might know the etag of the file now, and we should
         * incorporate it in the file name if we can */
        *path = mfree(*path);
        r = raw_pull_determine_path(p, suffix, path);
        if (r < 0)
                return r;

        r = install_file(
                        AT_FDCWD, *temp_path,
                        AT_FDCWD, *path,
                        INSTALL_READ_ONLY|
                        (p->flags & IMPORT_SYNC ? INSTALL_FSYNC_FULL : 0));
        if (r < 0)
                return log_error_errno(r, "Failed to move '%s' into place: %m", *path);

        *temp_path = mfree(*temp_path);
        return 1;
}

static void raw_pull_job_on_finished(PullJob *j) {
        int r;

        assert(j);
        RawPull *p = ASSERT_PTR(j->userdata);

        if (j->error != 0) {
                /* Only the main job and the checksum job are fatal if they fail. The other fails are just
                 * "decoration", that we'll download if we can. The signature job isn't fatal here because we
                 * might not actually need it in case Suse style signatures are used, that are inline in the
                 * checksum file. */

                if (j == p->raw_job) {
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
                else if (j == p->roothash_job)
                        log_info_errno(j->error, "Root hash file could not be retrieved, proceeding without.");
                else if (j == p->roothash_signature_job)
                        log_info_errno(j->error, "Root hash signature file could not be retrieved, proceeding without.");
                else if (j == p->verity_job)
                        log_info_errno(j->error, "Verity integrity file could not be retrieved, proceeding without.");
                else
                        assert_not_reached();
        }

        /* This is invoked if either the download completed successfully, or the download was skipped because
         * we already have the etag. In this case ->etag_exists is true.
         *
         * We only do something when we got all files */

        if (!raw_pull_is_done(p))
                return;

        if (p->signature_job && p->signature_job->error != 0) {
                VerificationStyle style;
                PullJob *verify_job;

                /* The signature job failed. Let's see if we actually need it */

                verify_job = p->checksum_job ?: p->raw_job; /* if the checksum job doesn't exist this must be
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
                        r = log_error_errno(p->signature_job->error,
                                            "Failed to retrieve signature file, cannot verify. (Try --verify=no?)");
                        goto finish;
                }
        }

        PullJob *jj;
        /* Let's close these auxiliary files now, we don't need access to them anymore. */
        FOREACH_ARGUMENT(jj, p->settings_job, p->roothash_job, p->roothash_signature_job, p->verity_job)
                pull_job_close_disk_fd(jj);

        if (!p->raw_job->etag_exists) {
                raw_pull_report_progress(p, RAW_VERIFYING);

                r = pull_verify(p->verify,
                                p->raw_job,
                                p->checksum_job,
                                p->signature_job,
                                p->settings_job,
                                p->roothash_job,
                                p->roothash_signature_job,
                                p->verity_job);
                if (r < 0)
                        goto finish;
        }

        if (p->flags & IMPORT_DIRECT) {
                assert(!p->settings_job);
                assert(!p->roothash_job);
                assert(!p->roothash_signature_job);
                assert(!p->verity_job);

                raw_pull_report_progress(p, RAW_FINALIZING);

                if (p->local) {
                        r = install_file(AT_FDCWD, p->local,
                                         AT_FDCWD, NULL,
                                         ((p->flags & IMPORT_READ_ONLY) && p->offset == UINT64_MAX ? INSTALL_READ_ONLY : 0) |
                                         (p->flags & IMPORT_SYNC ? INSTALL_FSYNC_FULL : 0));
                        if (r < 0) {
                                log_error_errno(r, "Failed to finalize raw file to '%s': %m", p->local);
                                goto finish;
                        }
                }
        } else {
                r = raw_pull_determine_path(p, ".raw", &p->final_path);
                if (r < 0)
                        goto finish;

                if (!p->raw_job->etag_exists) {
                        /* This is a new download, verify it, and move it into place */

                        assert(p->temp_path);
                        assert(p->final_path);

                        raw_pull_report_progress(p, RAW_UNPACKING);

                        r = raw_pull_maybe_convert_qcow2(p);
                        if (r < 0)
                                goto finish;

                        raw_pull_report_progress(p, RAW_FINALIZING);

                        r = install_file(AT_FDCWD, p->temp_path,
                                         AT_FDCWD, p->final_path,
                                         (p->flags & IMPORT_PULL_KEEP_DOWNLOAD ? INSTALL_READ_ONLY : 0) |
                                         (p->flags & IMPORT_SYNC ? INSTALL_FSYNC_FULL : 0));
                        if (r < 0) {
                                log_error_errno(r, "Failed to move raw file to '%s': %m", p->final_path);
                                goto finish;
                        }

                        p->temp_path = mfree(p->temp_path);

                        if (p->settings_job &&
                            p->settings_job->error == 0) {
                                r = raw_pull_rename_auxiliary_file(p, ".nspawn", &p->settings_temp_path, &p->settings_path);
                                if (r < 0)
                                        goto finish;
                        }

                        if (p->roothash_job &&
                            p->roothash_job->error == 0) {
                                r = raw_pull_rename_auxiliary_file(p, ".roothash", &p->roothash_temp_path, &p->roothash_path);
                                if (r < 0)
                                        goto finish;
                        }

                        if (p->roothash_signature_job &&
                            p->roothash_signature_job->error == 0) {
                                r = raw_pull_rename_auxiliary_file(p, ".roothash.p7s", &p->roothash_signature_temp_path, &p->roothash_signature_path);
                                if (r < 0)
                                        goto finish;
                        }

                        if (p->verity_job &&
                            p->verity_job->error == 0) {
                                r = raw_pull_rename_auxiliary_file(p, ".verity", &p->verity_temp_path, &p->verity_path);
                                if (r < 0)
                                        goto finish;
                        }
                }

                raw_pull_report_progress(p, RAW_COPYING);

                r = raw_pull_make_local_copy(p);
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

static int raw_pull_job_on_open_disk_generic(
                RawPull *p,
                PullJob *j,
                const char *extra,
                char **temp_path /* input + output */) {

        int r;

        assert(p);
        assert(j);
        assert(extra);
        assert(temp_path);

        assert(!FLAGS_SET(p->flags, IMPORT_DIRECT));

        if (!*temp_path) {
                r = tempfn_random_child(p->image_root, extra, temp_path);
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
        RawPull *p;
        int r;

        assert(j);
        assert(j->userdata);

        p = j->userdata;
        assert(p->raw_job == j);
        assert(j->disk_fd < 0);

        if (p->flags & IMPORT_DIRECT) {

                if (!p->local) { /* If no local name specified, the pull job will write its data to stdout */
                        j->disk_fd = STDOUT_FILENO;
                        j->close_disk_fd = false;
                        return 0;
                }

                (void) mkdir_parents_label(p->local, 0700);

                j->disk_fd = open(p->local, O_RDWR|O_NOCTTY|O_CLOEXEC|(p->offset == UINT64_MAX ? O_TRUNC|O_CREAT : 0), 0664);
                if (j->disk_fd < 0)
                        return log_error_errno(errno, "Failed to open destination '%s': %m", p->local);

                if (p->offset == UINT64_MAX)
                        (void) import_set_nocow_and_log(j->disk_fd, p->local);

        } else {
                r = raw_pull_job_on_open_disk_generic(p, j, "raw", &p->temp_path);
                if (r < 0)
                        return r;

                assert(p->offset == UINT64_MAX);
                (void) import_set_nocow_and_log(j->disk_fd, p->temp_path);
        }

        return 0;
}

static int raw_pull_job_on_open_disk_settings(PullJob *j) {
        RawPull *p;

        assert(j);
        assert(j->userdata);

        p = j->userdata;
        assert(p->settings_job == j);

        return raw_pull_job_on_open_disk_generic(p, j, "settings", &p->settings_temp_path);
}

static int raw_pull_job_on_open_disk_roothash(PullJob *j) {
        RawPull *p;

        assert(j);
        assert(j->userdata);

        p = j->userdata;
        assert(p->roothash_job == j);

        return raw_pull_job_on_open_disk_generic(p, j, "roothash", &p->roothash_temp_path);
}

static int raw_pull_job_on_open_disk_roothash_signature(PullJob *j) {
        RawPull *p;

        assert(j);
        assert(j->userdata);

        p = j->userdata;
        assert(p->roothash_signature_job == j);

        return raw_pull_job_on_open_disk_generic(p, j, "roothash.p7s", &p->roothash_signature_temp_path);
}

static int raw_pull_job_on_open_disk_verity(PullJob *j) {
        RawPull *p;

        assert(j);
        assert(j->userdata);

        p = j->userdata;
        assert(p->verity_job == j);

        return raw_pull_job_on_open_disk_generic(p, j, "verity", &p->verity_temp_path);
}

static void raw_pull_job_on_progress(PullJob *j) {
        RawPull *p;

        assert(j);
        assert(j->userdata);

        p = j->userdata;

        raw_pull_report_progress(p, RAW_DOWNLOADING);
}

int raw_pull_start(
                RawPull *p,
                const char *url,
                const char *local,
                uint64_t offset,
                uint64_t size_max,
                ImportFlags flags,
                ImportVerify verify,
                const struct iovec *checksum) {

        int r;

        assert(p);
        assert(url);
        assert(verify == _IMPORT_VERIFY_INVALID || verify < _IMPORT_VERIFY_MAX);
        assert(verify == _IMPORT_VERIFY_INVALID || verify >= 0);
        assert((verify < 0) || !iovec_is_set(checksum));
        assert(!(flags & ~IMPORT_PULL_FLAGS_MASK_RAW));
        assert(offset == UINT64_MAX || FLAGS_SET(flags, IMPORT_DIRECT));
        assert(!(flags & (IMPORT_PULL_SETTINGS|IMPORT_PULL_ROOTHASH|IMPORT_PULL_ROOTHASH_SIGNATURE|IMPORT_PULL_VERITY)) || !(flags & IMPORT_DIRECT));
        assert(!(flags & (IMPORT_PULL_SETTINGS|IMPORT_PULL_ROOTHASH|IMPORT_PULL_ROOTHASH_SIGNATURE|IMPORT_PULL_VERITY)) || !iovec_is_set(checksum));

        if (!http_url_is_valid(url) && !file_url_is_valid(url))
                return -EINVAL;

        if (local && !pull_validate_local(local, flags))
                return -EINVAL;

        if (p->raw_job)
                return -EBUSY;

        r = free_and_strdup(&p->local, local);
        if (r < 0)
                return r;

        p->flags = flags;
        p->verify = verify;

        /* Queue job for the image itself */
        r = pull_job_new(&p->raw_job, url, p->glue, p);
        if (r < 0)
                return r;

        p->raw_job->on_finished = raw_pull_job_on_finished;
        p->raw_job->on_open_disk = raw_pull_job_on_open_disk_raw;

        if (iovec_is_set(checksum)) {
                if (!iovec_memdup(checksum, &p->raw_job->expected_checksum))
                        return -ENOMEM;

                p->raw_job->calc_checksum = true;
        } else if (verify != IMPORT_VERIFY_NO) {
                /* Calculate checksum of the main download unless the users asks for a SHA256SUM file or its
                 * signature, which we let gpg verify instead. */

                r = pull_url_needs_checksum(url);
                if (r < 0)
                        return r;

                p->raw_job->calc_checksum = r;
                p->raw_job->force_memory = !r; /* make sure this is both written to disk if that's
                                                * requested and into memory, since we need to verify it */
        }

        if (size_max != UINT64_MAX)
                p->raw_job->uncompressed_max = size_max;
        if (offset != UINT64_MAX)
                p->raw_job->offset = p->offset = offset;

        if (!FLAGS_SET(flags, IMPORT_DIRECT)) {
                r = pull_find_old_etags(url, p->image_root, DT_REG, ".raw-", ".raw", &p->raw_job->old_etags);
                if (r < 0)
                        return r;
        }

        r = pull_make_verification_jobs(
                        &p->checksum_job,
                        &p->signature_job,
                        verify,
                        url,
                        p->glue,
                        raw_pull_job_on_finished,
                        p);
        if (r < 0)
                return r;

        if (FLAGS_SET(flags, IMPORT_PULL_SETTINGS)) {
                r = pull_make_auxiliary_job(
                                &p->settings_job,
                                url,
                                raw_strip_suffixes,
                                ".nspawn",
                                verify,
                                p->glue,
                                raw_pull_job_on_open_disk_settings,
                                raw_pull_job_on_finished,
                                p);
                if (r < 0)
                        return r;
        }

        if (FLAGS_SET(flags, IMPORT_PULL_ROOTHASH)) {
                r = pull_make_auxiliary_job(
                                &p->roothash_job,
                                url,
                                raw_strip_suffixes,
                                ".roothash",
                                verify,
                                p->glue,
                                raw_pull_job_on_open_disk_roothash,
                                raw_pull_job_on_finished,
                                p);
                if (r < 0)
                        return r;
        }

        if (FLAGS_SET(flags, IMPORT_PULL_ROOTHASH_SIGNATURE)) {
                r = pull_make_auxiliary_job(
                                &p->roothash_signature_job,
                                url,
                                raw_strip_suffixes,
                                ".roothash.p7s",
                                verify,
                                p->glue,
                                raw_pull_job_on_open_disk_roothash_signature,
                                raw_pull_job_on_finished,
                                p);
                if (r < 0)
                        return r;
        }

        if (FLAGS_SET(flags, IMPORT_PULL_VERITY)) {
                r = pull_make_auxiliary_job(
                                &p->verity_job,
                                url,
                                raw_strip_suffixes,
                                ".verity",
                                verify,
                                p->glue,
                                raw_pull_job_on_open_disk_verity,
                                raw_pull_job_on_finished,
                                p);
                if (r < 0)
                        return r;
        }

        PullJob *j;
        FOREACH_ARGUMENT(j,
                         p->raw_job,
                         p->checksum_job,
                         p->signature_job,
                         p->settings_job,
                         p->roothash_job,
                         p->roothash_signature_job,
                         p->verity_job) {

                if (!j)
                        continue;

                j->on_progress = raw_pull_job_on_progress;
                j->sync = FLAGS_SET(flags, IMPORT_SYNC);

                r = pull_job_begin(j);
                if (r < 0)
                        return r;
        }

        return 0;
}
