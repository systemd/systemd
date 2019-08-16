/* SPDX-License-Identifier: LGPL-2.1+ */

#include <sys/prctl.h>

#include "alloc-util.h"
#include "btrfs-util.h"
#include "capability-util.h"
#include "copy.h"
#include "dirent-util.h"
#include "escape.h"
#include "fd-util.h"
#include "io-util.h"
#include "path-util.h"
#include "process-util.h"
#include "pull-common.h"
#include "pull-job.h"
#include "rlimit-util.h"
#include "rm-rf.h"
#include "signal-util.h"
#include "siphash24.h"
#include "string-util.h"
#include "strv.h"
#include "util.h"
#include "web-util.h"

#define FILENAME_ESCAPE "/.#\"\'"
#define HASH_URL_THRESHOLD_LENGTH (_POSIX_PATH_MAX - 16)

int pull_find_old_etags(
                const char *url,
                const char *image_root,
                int dt,
                const char *prefix,
                const char *suffix,
                char ***etags) {

        _cleanup_free_ char *escaped_url = NULL;
        _cleanup_closedir_ DIR *d = NULL;
        _cleanup_strv_free_ char **l = NULL;
        struct dirent *de;
        int r;

        assert(url);
        assert(etags);

        if (!image_root)
                image_root = "/var/lib/machines";

        escaped_url = xescape(url, FILENAME_ESCAPE);
        if (!escaped_url)
                return -ENOMEM;

        d = opendir(image_root);
        if (!d) {
                if (errno == ENOENT) {
                        *etags = NULL;
                        return 0;
                }

                return -errno;
        }

        FOREACH_DIRENT_ALL(de, d, return -errno) {
                _cleanup_free_ char *u = NULL;
                const char *a, *b;

                if (de->d_type != DT_UNKNOWN &&
                    de->d_type != dt)
                        continue;

                if (prefix) {
                        a = startswith(de->d_name, prefix);
                        if (!a)
                                continue;
                } else
                        a = de->d_name;

                a = startswith(a, escaped_url);
                if (!a)
                        continue;

                a = startswith(a, ".");
                if (!a)
                        continue;

                if (suffix) {
                        b = endswith(de->d_name, suffix);
                        if (!b)
                                continue;
                } else
                        b = strchr(de->d_name, 0);

                if (a >= b)
                        continue;

                r = cunescape_length(a, b - a, 0, &u);
                if (r < 0)
                        return r;

                if (!http_etag_is_valid(u))
                        continue;

                r = strv_consume(&l, TAKE_PTR(u));
                if (r < 0)
                        return r;
        }

        *etags = TAKE_PTR(l);

        return 0;
}

int pull_make_local_copy(const char *final, const char *image_root, const char *local, bool force_local) {
        const char *p;
        int r;

        assert(final);
        assert(local);

        if (!image_root)
                image_root = "/var/lib/machines";

        p = prefix_roota(image_root, local);

        if (force_local)
                (void) rm_rf(p, REMOVE_ROOT|REMOVE_PHYSICAL|REMOVE_SUBVOLUME);

        r = btrfs_subvol_snapshot(final, p,
                                  BTRFS_SNAPSHOT_QUOTA|
                                  BTRFS_SNAPSHOT_FALLBACK_COPY|
                                  BTRFS_SNAPSHOT_FALLBACK_DIRECTORY|
                                  BTRFS_SNAPSHOT_RECURSIVE);
        if (r < 0)
                return log_error_errno(r, "Failed to create local image: %m");

        log_info("Created new local image '%s'.", local);

        return 0;
}

static int hash_url(const char *url, char **ret) {
        uint64_t h;
        static const sd_id128_t k = SD_ID128_ARRAY(df,89,16,87,01,cc,42,30,98,ab,4a,19,a6,a5,63,4f);

        assert(url);

        h = siphash24(url, strlen(url), k.bytes);
        if (asprintf(ret, "%"PRIx64, h) < 0)
                return -ENOMEM;

        return 0;
}

int pull_make_path(const char *url, const char *etag, const char *image_root, const char *prefix, const char *suffix, char **ret) {
        _cleanup_free_ char *escaped_url = NULL, *escaped_etag = NULL;
        char *path;

        assert(url);
        assert(ret);

        if (!image_root)
                image_root = "/var/lib/machines";

        escaped_url = xescape(url, FILENAME_ESCAPE);
        if (!escaped_url)
                return -ENOMEM;

        if (etag) {
                escaped_etag = xescape(etag, FILENAME_ESCAPE);
                if (!escaped_etag)
                        return -ENOMEM;
        }

        path = strjoin(image_root, "/", strempty(prefix), escaped_url, escaped_etag ? "." : "",
                       strempty(escaped_etag), strempty(suffix));
        if (!path)
                return -ENOMEM;

        /* URLs might make the path longer than the maximum allowed length for a file name.
         * When that happens, a URL hash is used instead. Paths returned by this function
         * can be later used with tempfn_random() which adds 16 bytes to the resulting name. */
        if (strlen(path) >= HASH_URL_THRESHOLD_LENGTH) {
                _cleanup_free_ char *hash = NULL;
                int r;

                free(path);

                r = hash_url(url, &hash);
                if (r < 0)
                        return r;

                path = strjoin(image_root, "/", strempty(prefix), hash, escaped_etag ? "." : "",
                               strempty(escaped_etag), strempty(suffix));
                if (!path)
                        return -ENOMEM;
        }

        *ret = path;
        return 0;
}

int pull_make_auxiliary_job(
                PullJob **ret,
                const char *url,
                int (*strip_suffixes)(const char *name, char **ret),
                const char *suffix,
                CurlGlue *glue,
                PullJobFinished on_finished,
                void *userdata) {

        _cleanup_free_ char *last_component = NULL, *ll = NULL, *auxiliary_url = NULL;
        _cleanup_(pull_job_unrefp) PullJob *job = NULL;
        const char *q;
        int r;

        assert(ret);
        assert(url);
        assert(strip_suffixes);
        assert(glue);

        r = import_url_last_component(url, &last_component);
        if (r < 0)
                return r;

        r = strip_suffixes(last_component, &ll);
        if (r < 0)
                return r;

        q = strjoina(ll, suffix);

        r = import_url_change_last_component(url, q, &auxiliary_url);
        if (r < 0)
                return r;

        r = pull_job_new(&job, auxiliary_url, glue, userdata);
        if (r < 0)
                return r;

        job->on_finished = on_finished;
        job->compressed_max = job->uncompressed_max = 1ULL * 1024ULL * 1024ULL;

        *ret = TAKE_PTR(job);

        return 0;
}

int pull_make_verification_jobs(
                PullJob **ret_checksum_job,
                PullJob **ret_signature_job,
                ImportVerify verify,
                const char *url,
                CurlGlue *glue,
                PullJobFinished on_finished,
                void *userdata) {

        _cleanup_(pull_job_unrefp) PullJob *checksum_job = NULL, *signature_job = NULL;
        int r;
        const char *chksums = NULL;

        assert(ret_checksum_job);
        assert(ret_signature_job);
        assert(verify >= 0);
        assert(verify < _IMPORT_VERIFY_MAX);
        assert(url);
        assert(glue);

        if (verify != IMPORT_VERIFY_NO) {
                _cleanup_free_ char *checksum_url = NULL, *fn = NULL;

                /* Queue jobs for the checksum file for the image. */
                r = import_url_last_component(url, &fn);
                if (r < 0)
                        return r;

                chksums = strjoina(fn, ".sha256");

                r = import_url_change_last_component(url, chksums, &checksum_url);
                if (r < 0)
                        return r;

                r = pull_job_new(&checksum_job, checksum_url, glue, userdata);
                if (r < 0)
                        return r;

                checksum_job->on_finished = on_finished;
                checksum_job->uncompressed_max = checksum_job->compressed_max = 1ULL * 1024ULL * 1024ULL;
        }

        if (verify == IMPORT_VERIFY_SIGNATURE) {
                _cleanup_free_ char *signature_url = NULL;

                /* Queue job for the SHA256SUMS.gpg file for the image. */
                r = import_url_change_last_component(url, "SHA256SUMS.gpg", &signature_url);
                if (r < 0)
                        return r;

                r = pull_job_new(&signature_job, signature_url, glue, userdata);
                if (r < 0)
                        return r;

                signature_job->on_finished = on_finished;
                signature_job->uncompressed_max = signature_job->compressed_max = 1ULL * 1024ULL * 1024ULL;
        }

        *ret_checksum_job = checksum_job;
        *ret_signature_job = signature_job;

        checksum_job = signature_job = NULL;

        return 0;
}

static int verify_one(PullJob *checksum_job, PullJob *job) {
        _cleanup_free_ char *fn = NULL;
        const char *line, *p;
        int r;

        assert(checksum_job);

        if (!job)
                return 0;

        assert(IN_SET(job->state, PULL_JOB_DONE, PULL_JOB_FAILED));

        /* Don't verify the checksum if we didn't actually successfully download something new */
        if (job->state != PULL_JOB_DONE)
                return 0;
        if (job->error != 0)
                return 0;
        if (job->etag_exists)
                return 0;

        assert(job->calc_checksum);
        assert(job->checksum);

        r = import_url_last_component(job->url, &fn);
        if (r < 0)
                return log_oom();

        if (!filename_is_valid(fn))
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Cannot verify checksum, could not determine server-side file name.");

        line = strjoina(job->checksum, " *", fn, "\n");

        p = memmem(checksum_job->payload,
                   checksum_job->payload_size,
                   line,
                   strlen(line));

        if (!p) {
                line = strjoina(job->checksum, "  ", fn, "\n");

                p = memmem(checksum_job->payload,
                        checksum_job->payload_size,
                        line,
                        strlen(line));
        }

        if (!p || (p != (char*) checksum_job->payload && p[-1] != '\n'))
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "DOWNLOAD INVALID: Checksum of %s file did not checkout, file has been tampered with.", fn);

        log_info("SHA256 checksum of %s is valid.", job->url);
        return 1;
}

int pull_verify(PullJob *main_job,
                PullJob *roothash_job,
                PullJob *settings_job,
                PullJob *checksum_job,
                PullJob *signature_job) {

        _cleanup_close_pair_ int gpg_pipe[2] = { -1, -1 };
        _cleanup_close_ int sig_file = -1;
        char sig_file_path[] = "/tmp/sigXXXXXX", gpg_home[] = "/tmp/gpghomeXXXXXX";
        _cleanup_(sigkill_waitp) pid_t pid = 0;
        bool gpg_home_created = false;
        int r;

        assert(main_job);
        assert(main_job->state == PULL_JOB_DONE);

        if (!checksum_job)
                return 0;

        assert(main_job->calc_checksum);
        assert(main_job->checksum);

        assert(checksum_job->state == PULL_JOB_DONE);

        if (!checksum_job->payload || checksum_job->payload_size <= 0) {
                log_error("Checksum is empty, cannot verify.");
                return -EBADMSG;
        }

        r = verify_one(checksum_job, main_job);
        if (r < 0)
                return r;

        r = verify_one(checksum_job, roothash_job);
        if (r < 0)
                return r;

        r = verify_one(checksum_job, settings_job);
        if (r < 0)
                return r;

        if (!signature_job)
                return 0;

        if (checksum_job->style == VERIFICATION_PER_FILE)
                signature_job = checksum_job;

        assert(signature_job->state == PULL_JOB_DONE);

        if (!signature_job->payload || signature_job->payload_size <= 0) {
                log_error("Signature is empty, cannot verify.");
                return -EBADMSG;
        }

        r = pipe2(gpg_pipe, O_CLOEXEC);
        if (r < 0)
                return log_error_errno(errno, "Failed to create pipe for gpg: %m");

        sig_file = mkostemp(sig_file_path, O_RDWR);
        if (sig_file < 0)
                return log_error_errno(errno, "Failed to create temporary file: %m");

        r = loop_write(sig_file, signature_job->payload, signature_job->payload_size, false);
        if (r < 0) {
                log_error_errno(r, "Failed to write to temporary file: %m");
                goto finish;
        }

        if (!mkdtemp(gpg_home)) {
                r = log_error_errno(errno, "Failed to create temporary home for gpg: %m");
                goto finish;
        }

        gpg_home_created = true;

        r = safe_fork("(gpg)", FORK_RESET_SIGNALS|FORK_DEATHSIG|FORK_LOG, &pid);
        if (r < 0)
                return r;
        if (r == 0) {
                const char *cmd[] = {
                        "gpg",
                        "--no-options",
                        "--no-default-keyring",
                        "--no-auto-key-locate",
                        "--no-auto-check-trustdb",
                        "--batch",
                        "--trust-model=always",
                        NULL, /* --homedir=  */
                        NULL, /* --keyring= */
                        NULL, /* --verify */
                        NULL, /* signature file */
                        NULL, /* dash */
                        NULL  /* trailing NULL */
                };
                unsigned k = ELEMENTSOF(cmd) - 6;

                /* Child */

                gpg_pipe[1] = safe_close(gpg_pipe[1]);

                r = rearrange_stdio(gpg_pipe[0], -1, STDERR_FILENO);
                if (r < 0) {
                        log_error_errno(r, "Failed to rearrange stdin/stdout: %m");
                        _exit(EXIT_FAILURE);
                }

                (void) rlimit_nofile_safe();

                cmd[k++] = strjoina("--homedir=", gpg_home);

                /* We add the user keyring only to the command line
                 * arguments, if it's around since gpg fails
                 * otherwise. */
                if (access(USER_KEYRING_PATH, F_OK) >= 0)
                        cmd[k++] = "--keyring=" USER_KEYRING_PATH;
                else
                        cmd[k++] = "--keyring=" VENDOR_KEYRING_PATH;

                cmd[k++] = "--verify";
                if (checksum_job->style == VERIFICATION_PER_DIRECTORY) {
                        cmd[k++] = sig_file_path;
                        cmd[k++] = "-";
                        cmd[k++] = NULL;
                }

                execvp("gpg2", (char * const *) cmd);
                execvp("gpg", (char * const *) cmd);
                log_error_errno(errno, "Failed to execute gpg: %m");
                _exit(EXIT_FAILURE);
        }

        gpg_pipe[0] = safe_close(gpg_pipe[0]);

        r = loop_write(gpg_pipe[1], checksum_job->payload, checksum_job->payload_size, false);
        if (r < 0) {
                log_error_errno(r, "Failed to write to pipe: %m");
                goto finish;
        }

        gpg_pipe[1] = safe_close(gpg_pipe[1]);

        r = wait_for_terminate_and_check("gpg", pid, WAIT_LOG_ABNORMAL);
        pid = 0;
        if (r < 0)
                goto finish;
        if (r != EXIT_SUCCESS) {
                log_error("DOWNLOAD INVALID: Signature verification failed.");
                r = -EBADMSG;
        } else {
                log_info("Signature verification succeeded.");
                r = 0;
        }

finish:
        (void) unlink(sig_file_path);

        if (gpg_home_created)
                (void) rm_rf(gpg_home, REMOVE_ROOT|REMOVE_PHYSICAL);

        return r;
}
