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
#include <sys/prctl.h>
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
        ImportJob *signature_job;

        RawImportFinished on_finished;
        void *userdata;

        char *local;
        bool force_local;

        char *temp_path;
        char *final_path;

        ImportVerify verify;
};

RawImport* raw_import_unref(RawImport *i) {
        if (!i)
                return NULL;

        import_job_unref(i->raw_job);
        import_job_unref(i->sha256sums_job);
        import_job_unref(i->signature_job);

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
        _cleanup_close_pair_ int gpg_pipe[2] = { -1, -1 };
        _cleanup_free_ char *fn = NULL;
        _cleanup_close_ int sig_file = -1;
        const char *p, *line;
        char sig_file_path[] = "/tmp/sigXXXXXX";
        _cleanup_sigkill_wait_ pid_t pid = 0;
        int r;

        assert(i);

        assert(i->raw_job);

        if (!i->sha256sums_job)
                return 0;

        assert(i->raw_job->state == IMPORT_JOB_DONE);
        assert(i->raw_job->sha256);

        assert(i->sha256sums_job->state == IMPORT_JOB_DONE);
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

        if (!i->signature_job)
                return 0;

        assert(i->signature_job->state == IMPORT_JOB_DONE);
        assert(i->signature_job->payload);
        assert(i->signature_job->payload_size > 0);

        r = pipe2(gpg_pipe, O_CLOEXEC);
        if (r < 0)
                return log_error_errno(errno, "Failed to create pipe: %m");

        sig_file = mkostemp(sig_file_path, O_RDWR);
        if (sig_file < 0)
                return log_error_errno(errno, "Failed to create temporary file: %m");

        r = loop_write(sig_file, i->signature_job->payload, i->signature_job->payload_size, false);
        if (r < 0) {
                log_error_errno(r, "Failed to write to temporary file: %m");
                goto finish;
        }

        pid = fork();
        if (pid < 0)
                return log_error_errno(errno, "Failed to fork off gpg: %m");
        if (pid == 0) {
                const char *cmd[] = {
                        "gpg",
                        "--no-options",
                        "--no-default-keyring",
                        "--no-auto-key-locate",
                        "--no-auto-check-trustdb",
                        "--batch",
                        "--trust-model=always",
                        "--keyring=" VENDOR_KEYRING_PATH,
                        NULL, /* maybe user keyring */
                        NULL, /* --verify */
                        NULL, /* signature file */
                        NULL, /* dash */
                        NULL  /* trailing NULL */
                };
                unsigned k = ELEMENTSOF(cmd) - 5;
                int null_fd;

                /* Child */

                reset_all_signal_handlers();
                reset_signal_mask();
                assert_se(prctl(PR_SET_PDEATHSIG, SIGTERM) == 0);

                gpg_pipe[1] = safe_close(gpg_pipe[1]);

                if (dup2(gpg_pipe[0], STDIN_FILENO) != STDIN_FILENO) {
                        log_error_errno(errno, "Failed to dup2() fd: %m");
                        _exit(EXIT_FAILURE);
                }

                if (gpg_pipe[0] != STDIN_FILENO)
                        gpg_pipe[0] = safe_close(gpg_pipe[0]);

                null_fd = open("/dev/null", O_WRONLY|O_NOCTTY);
                if (null_fd < 0) {
                        log_error_errno(errno, "Failed to open /dev/null: %m");
                        _exit(EXIT_FAILURE);
                }

                if (dup2(null_fd, STDOUT_FILENO) != STDOUT_FILENO) {
                        log_error_errno(errno, "Failed to dup2() fd: %m");
                        _exit(EXIT_FAILURE);
                }

                if (null_fd != STDOUT_FILENO)
                        null_fd = safe_close(null_fd);

                /* We add the user keyring only to the command line
                 * arguments, if it's around since gpg fails
                 * otherwise. */
                if (access(USER_KEYRING_PATH, F_OK) >= 0)
                        cmd[k++] = "--keyring=" USER_KEYRING_PATH;

                cmd[k++] = "--verify";
                cmd[k++] = sig_file_path;
                cmd[k++] = "-";
                cmd[k++] = NULL;

                execvp("gpg", (char * const *) cmd);
                log_error_errno(errno, "Failed to execute gpg: %m");
                _exit(EXIT_FAILURE);
        }

        gpg_pipe[0] = safe_close(gpg_pipe[0]);

        r = loop_write(gpg_pipe[1], i->sha256sums_job->payload, i->sha256sums_job->payload_size, false);
        if (r < 0) {
                log_error_errno(r, "Failed to write to pipe: %m");
                goto finish;
        }

        gpg_pipe[1] = safe_close(gpg_pipe[1]);

        r = wait_for_terminate_and_warn("gpg", pid, true);
        pid = 0;
        if (r < 0)
                goto finish;
        if (r > 0) {
                log_error("Signature verification failed.");
                r = -EBADMSG;
        } else {
                log_info("Signature verification succeeded.");
                r = 0;
        }

finish:
        if (sig_file >= 0)
                unlink(sig_file_path);

        return r;
}

static void raw_import_job_on_finished(ImportJob *j) {
        RawImport *i;
        int r;

        assert(j);
        assert(j->userdata);

        i = j->userdata;
        if (j->error != 0) {
                if (j == i->sha256sums_job)
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
         * already have the etag. In this case ->etag_exists is
         * true.
         *
         * We only do something when we got all three files */

        if (!IMPORT_JOB_STATE_IS_COMPLETE(i->raw_job))
                return;
        if (i->sha256sums_job && !IMPORT_JOB_STATE_IS_COMPLETE(i->sha256sums_job))
                return;
        if (i->signature_job && !IMPORT_JOB_STATE_IS_COMPLETE(i->signature_job))
                return;

        if (!i->raw_job->etag_exists) {
                assert(i->raw_job->disk_fd >= 0);

                r = raw_import_verify_sha256sum(i);
                if (r < 0)
                        goto finish;

                r = raw_import_maybe_convert_qcow2(i);
                if (r < 0)
                        goto finish;

                r = import_make_read_only_fd(i->raw_job->disk_fd);
                if (r < 0)
                        goto finish;

                r = rename(i->temp_path, i->final_path);
                if (r < 0) {
                        r = log_error_errno(errno, "Failed to move RAW file into place: %m");
                        goto finish;
                }

                free(i->temp_path);
                i->temp_path = NULL;
        }

        r = raw_import_make_local_copy(i);
        if (r < 0)
                goto finish;

        r = 0;

finish:
        if (i->on_finished)
                i->on_finished(i, r, i->userdata);
        else
                sd_event_exit(i->event, r);
}

static int raw_import_job_on_open_disk(ImportJob *j) {
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

int raw_import_pull(RawImport *i, const char *url, const char *local, bool force_local, ImportVerify verify) {
        int r;

        assert(i);
        assert(verify < _IMPORT_VERIFY_MAX);
        assert(verify >= 0);

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
        i->verify = verify;

        /* Queue job for the image itself */
        r = import_job_new(&i->raw_job, url, i->glue, i);
        if (r < 0)
                return r;

        i->raw_job->on_finished = raw_import_job_on_finished;
        i->raw_job->on_open_disk = raw_import_job_on_open_disk;
        i->raw_job->calc_hash = true;

        r = import_find_old_etags(url, i->image_root, DT_REG, ".raw-", ".raw", &i->raw_job->old_etags);
        if (r < 0)
                return r;

        if (verify != IMPORT_VERIFY_NO) {
                _cleanup_free_ char *sha256sums_url = NULL;

                /* Queue job for the SHA256SUMS file for the image */
                r = import_url_change_last_component(url, "SHA256SUMS", &sha256sums_url);
                if (r < 0)
                        return r;

                r = import_job_new(&i->sha256sums_job, sha256sums_url, i->glue, i);
                if (r < 0)
                        return r;

                i->sha256sums_job->on_finished = raw_import_job_on_finished;
                i->sha256sums_job->uncompressed_max = i->sha256sums_job->compressed_max = 1ULL * 1024ULL * 1024ULL;
        }

        if (verify == IMPORT_VERIFY_SIGNATURE) {
                _cleanup_free_ char *sha256sums_sig_url = NULL;

                /* Queue job for the SHA256SUMS.gpg file for the image. */
                r = import_url_change_last_component(url, "SHA256SUMS.gpg", &sha256sums_sig_url);
                if (r < 0)
                        return r;

                r = import_job_new(&i->signature_job, sha256sums_sig_url, i->glue, i);
                if (r < 0)
                        return r;

                i->signature_job->on_finished = raw_import_job_on_finished;
                i->signature_job->uncompressed_max = i->signature_job->compressed_max = 1ULL * 1024ULL * 1024ULL;
        }

        r = import_job_begin(i->raw_job);
        if (r < 0)
                return r;

        if (i->sha256sums_job) {
                r = import_job_begin(i->sha256sums_job);
                if (r < 0)
                        return r;
        }

        if (i->signature_job) {
                r = import_job_begin(i->signature_job);
                if (r < 0)
                        return r;
        }

        return 0;
}
