/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

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

#include <sys/xattr.h>
#include <linux/fs.h>
#include <curl/curl.h>
#include <gcrypt.h>

#include "utf8.h"
#include "strv.h"
#include "copy.h"
#include "btrfs-util.h"
#include "util.h"
#include "macro.h"
#include "mkdir.h"
#include "curl-util.h"
#include "qcow2-util.h"
#include "import-job.h"
#include "import-util.h"
#include "import-raw.h"

typedef struct RawImportFile RawImportFile;

struct RawImport {
        sd_event *event;
        CurlGlue *glue;

        char *image_root;

        ImportJob *raw_job;
        ImportJob *sha256sums_job;

        RawImportFinished on_finished;
        void *userdata;

        char *local;
        bool force_local;

        char *temp_path;
        char *final_path;
};

RawImport* raw_import_unref(RawImport *i) {
        if (!i)
                return NULL;

        import_job_unref(i->raw_job);

        curl_glue_unref(i->glue);
        sd_event_unref(i->event);

        if (i->temp_path) {
                (void) unlink(i->temp_path);
                free(i->temp_path);
        }

        free(i->final_path);
        free(i->image_root);
        free(i->local);
        free(i);

        return NULL;
}

int raw_import_new(RawImport **ret, sd_event *event, const char *image_root, RawImportFinished on_finished, void *userdata) {
        _cleanup_(raw_import_unrefp) RawImport *i = NULL;
        int r;

        assert(ret);

        i = new0(RawImport, 1);
        if (!i)
                return -ENOMEM;

        i->on_finished = on_finished;
        i->userdata = userdata;

        i->image_root = strdup(image_root ?: "/var/lib/machines");
        if (!i->image_root)
                return -ENOMEM;

        if (event)
                i->event = sd_event_ref(event);
        else {
                r = sd_event_default(&i->event);
                if (r < 0)
                        return r;
        }

        r = curl_glue_new(&i->glue, i->event);
        if (r < 0)
                return r;

        i->glue->on_finished = import_job_curl_on_finished;
        i->glue->userdata = i;

        *ret = i;
        i = NULL;

        return 0;
}

static int raw_import_maybe_convert_qcow2(RawImport *i) {
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
        r = tempfn_random(i->final_path, &t);
        if (r < 0)
                return log_oom();

        converted_fd = open(t, O_RDWR|O_CREAT|O_EXCL|O_NOCTTY|O_CLOEXEC, 0644);
        if (converted_fd < 0)
                return log_error_errno(errno, "Failed to create %s: %m", t);

        r = chattr_fd(converted_fd, true, FS_NOCOW_FL);
        if (r < 0)
                log_warning_errno(errno, "Failed to set file attributes on %s: %m", t);

        log_info("Unpacking QCOW2 file.");

        r = qcow2_convert(i->raw_job->disk_fd, converted_fd);
        if (r < 0) {
                unlink(t);
                return log_error_errno(r, "Failed to convert qcow2 image: %m");
        }

        unlink(i->temp_path);
        free(i->temp_path);

        i->temp_path = t;
        t = NULL;

        safe_close(i->raw_job->disk_fd);
        i->raw_job->disk_fd = converted_fd;
        converted_fd = -1;

        return 1;
}

static int raw_import_make_local_copy(RawImport *i) {
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

                if (!i->final_path) {
                        r = import_make_path(i->raw_job->url, i->raw_job->etag, i->image_root, ".raw-", ".raw", &i->final_path);
                        if (r < 0)
                                return log_oom();
                }

                i->raw_job->disk_fd = open(i->final_path, O_RDONLY|O_NOCTTY|O_CLOEXEC);
                if (i->raw_job->disk_fd < 0)
                        return log_error_errno(errno, "Failed to open vendor image: %m");
        } else {
                /* We freshly downloaded the image, use it */

                assert(i->raw_job->disk_fd >= 0);

                if (lseek(i->raw_job->disk_fd, SEEK_SET, 0) == (off_t) -1)
                        return log_error_errno(errno, "Failed to seek to beginning of vendor image: %m");
        }

        p = strappenda(i->image_root, "/", i->local, ".raw");

        if (i->force_local) {
                (void) btrfs_subvol_remove(p);
                (void) rm_rf_dangerous(p, false, true, false);
        }

        r = tempfn_random(p, &tp);
        if (r < 0)
                return log_oom();

        dfd = open(tp, O_WRONLY|O_CREAT|O_EXCL|O_NOCTTY|O_CLOEXEC, 0664);
        if (dfd < 0)
                return log_error_errno(errno, "Failed to create writable copy of image: %m");

        /* Turn off COW writing. This should greatly improve
         * performance on COW file systems like btrfs, since it
         * reduces fragmentation caused by not allowing in-place
         * writes. */
        r = chattr_fd(dfd, true, FS_NOCOW_FL);
        if (r < 0)
                log_warning_errno(errno, "Failed to set file attributes on %s: %m", tp);

        r = copy_bytes(i->raw_job->disk_fd, dfd, (off_t) -1, true);
        if (r < 0) {
                unlink(tp);
                return log_error_errno(r, "Failed to make writable copy of image: %m");
        }

        (void) copy_times(i->raw_job->disk_fd, dfd);
        (void) copy_xattr(i->raw_job->disk_fd, dfd);

        dfd = safe_close(dfd);

        r = rename(tp, p);
        if (r < 0)  {
                unlink(tp);
                return log_error_errno(errno, "Failed to move writable image into place: %m");
        }

        log_info("Created new local image '%s'.", i->local);
        return 0;
}

static int raw_import_verify_sha256sum(RawImport *i) {
        _cleanup_free_ char *fn = NULL;
        const char *p, *line;
        int r;

        assert(i);

        assert(i->raw_job);
        assert(i->raw_job->sha256);

        assert(i->sha256sums_job);
        assert(i->sha256sums_job->payload);
        assert(i->sha256sums_job->payload_size > 0);

        r = import_url_last_component(i->raw_job->url, &fn);
        if (r < 0)
                return log_oom();

        if (!filename_is_valid(fn)) {
                log_error("Cannot verify checksum, could not determine valid server-side file name.");
                return -EBADMSG;
        }

        line = strappenda(i->raw_job->sha256, " *", fn, "\n");

        p = memmem(i->sha256sums_job->payload,
                   i->sha256sums_job->payload_size,
                   line,
                   strlen(line));

        if (!p || (p != (char*) i->sha256sums_job->payload && p[-1] != '\n')) {
                log_error("Checksum did not check out, payload has been tempered with.");
                return -EBADMSG;
        }

        log_info("SHA256 checksum of %s is valid.", i->raw_job->url);

        return 0;
}

static int raw_import_finalize(RawImport *i) {
        int r;

        assert(i);

        if (!IMPORT_JOB_STATE_IS_COMPLETE(i->raw_job) ||
            !IMPORT_JOB_STATE_IS_COMPLETE(i->sha256sums_job))
                return 0;

        if (!i->raw_job->etag_exists) {
                assert(i->temp_path);
                assert(i->final_path);
                assert(i->raw_job->disk_fd >= 0);

                r = raw_import_verify_sha256sum(i);
                if (r < 0)
                        return r;

                r = rename(i->temp_path, i->final_path);
                if (r < 0)
                        return log_error_errno(errno, "Failed to move RAW file into place: %m");

                free(i->temp_path);
                i->temp_path = NULL;
        }

        r = raw_import_make_local_copy(i);
        if (r < 0)
                return r;

        i->raw_job->disk_fd = safe_close(i->raw_job->disk_fd);

        return 1;
}

static void raw_import_invoke_finished(RawImport *i, int r) {
        assert(i);

        if (i->on_finished)
                i->on_finished(i, r, i->userdata);
        else
                sd_event_exit(i->event, r);
}

static void raw_import_raw_job_on_finished(ImportJob *j) {
        RawImport *i;
        int r;

        assert(j);
        assert(j->userdata);

        i = j->userdata;
        if (j->error != 0) {
                r = j->error;
                goto finish;
        }

        /* This is invoked if either the download completed
         * successfully, or the download was skipped because we
         * already have the etag. In this case ->etag_exists is
         * true. */

        if (!j->etag_exists) {
                assert(j->disk_fd >= 0);

                r = raw_import_maybe_convert_qcow2(i);
                if (r < 0)
                        goto finish;

                r = import_make_read_only_fd(j->disk_fd);
                if (r < 0)
                        goto finish;
        }

        r = raw_import_finalize(i);
        if (r < 0)
                goto finish;
        if (r == 0)
                return;

        r = 0;

finish:
        raw_import_invoke_finished(i, r);
}

static void raw_import_sha256sums_job_on_finished(ImportJob *j) {
        RawImport *i;
        int r;

        assert(j);
        assert(j->userdata);

        i = j->userdata;
        if (j->error != 0) {
                r = j->error;
                goto finish;
        }

        r = raw_import_finalize(i);
        if (r < 0)
                goto finish;
        if (r == 0)
                return;

        r = 0;
finish:
        raw_import_invoke_finished(i, r);
}

static int raw_import_raw_job_on_open_disk(ImportJob *j) {
        RawImport *i;
        int r;

        assert(j);
        assert(j->userdata);

        i = j->userdata;

        r = import_make_path(j->url, j->etag, i->image_root, ".raw-", ".raw", &i->final_path);
        if (r < 0)
                return log_oom();

        r = tempfn_random(i->final_path, &i->temp_path);
        if (r <0)
                return log_oom();

        mkdir_parents_label(i->temp_path, 0700);

        j->disk_fd = open(i->temp_path, O_RDWR|O_CREAT|O_EXCL|O_NOCTTY|O_CLOEXEC, 0644);
        if (j->disk_fd < 0)
                return log_error_errno(errno, "Failed to create %s: %m", i->temp_path);

        r = chattr_fd(j->disk_fd, true, FS_NOCOW_FL);
        if (r < 0)
                log_warning_errno(errno, "Failed to set file attributes on %s: %m", i->temp_path);

        return 0;
}

int raw_import_pull(RawImport *i, const char *url, const char *local, bool force_local) {
        _cleanup_free_ char *sha256sums_url = NULL;
        int r;

        assert(i);

        if (i->raw_job)
                return -EBUSY;

        if (!http_url_is_valid(url))
                return -EINVAL;

        if (local && !machine_name_is_valid(local))
                return -EINVAL;

        r = free_and_strdup(&i->local, local);
        if (r < 0)
                return r;
        i->force_local = force_local;

        /* Queue job for the image itself */
        r = import_job_new(&i->raw_job, url, i->glue, i);
        if (r < 0)
                return r;

        i->raw_job->on_finished = raw_import_raw_job_on_finished;
        i->raw_job->on_open_disk = raw_import_raw_job_on_open_disk;
        i->raw_job->calc_hash = true;

        r = import_find_old_etags(url, i->image_root, DT_REG, ".raw-", ".raw", &i->raw_job->old_etags);
        if (r < 0)
                return r;

        /* Queue job for the SHA256SUMS file for the image */
        r = import_url_change_last_component(url, "SHA256SUMS", &sha256sums_url);
        if (r < 0)
                return r;

        r = import_job_new(&i->sha256sums_job, sha256sums_url, i->glue, i);
        if (r < 0)
                return r;

        i->sha256sums_job->on_finished = raw_import_sha256sums_job_on_finished;
        i->sha256sums_job->uncompressed_max = i->sha256sums_job->compressed_max = 1ULL * 1024ULL * 1024ULL;

        r = import_job_begin(i->raw_job);
        if (r < 0)
                return r;

        r = import_job_begin(i->sha256sums_job);
        if (r < 0)
                return r;

        return 0;
}
