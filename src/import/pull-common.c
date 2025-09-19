/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-id128.h"

#include "alloc-util.h"
#include "dirent-util.h"
#include "escape.h"
#include "fd-util.h"
#include "io-util.h"
#include "log.h"
#include "memory-util.h"
#include "os-util.h"
#include "path-util.h"
#include "process-util.h"
#include "pull-common.h"
#include "pull-job.h"
#include "rm-rf.h"
#include "siphash24.h"
#include "string-util.h"
#include "strv.h"
#include "tmpfile-util.h"
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

        int r;

        assert(url);
        assert(image_root);
        assert(etags);

        _cleanup_free_ char *escaped_url = xescape(url, FILENAME_ESCAPE);
        if (!escaped_url)
                return -ENOMEM;

        _cleanup_closedir_ DIR *d = opendir(image_root);
        if (!d) {
                if (errno == ENOENT) {
                        *etags = NULL;
                        return 0;
                }

                return -errno;
        }

        _cleanup_strv_free_ char **ans = NULL;

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

                ssize_t l = cunescape_length(a, b - a, 0, &u);
                if (l < 0) {
                        assert(l >= INT8_MIN);
                        return l;
                }

                if (!http_etag_is_valid(u))
                        continue;

                r = strv_consume(&ans, TAKE_PTR(u));
                if (r < 0)
                        return r;
        }

        *etags = TAKE_PTR(ans);

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
        assert(image_root);
        assert(ret);

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
                ImportVerify verify,
                CurlGlue *glue,
                PullJobOpenDisk on_open_disk,
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

        job->on_open_disk = on_open_disk;
        job->on_finished = on_finished;
        job->compressed_max = job->uncompressed_max = 1ULL * 1024ULL * 1024ULL;
        job->calc_checksum = IN_SET(verify, IMPORT_VERIFY_CHECKSUM, IMPORT_VERIFY_SIGNATURE);

        *ret = TAKE_PTR(job);
        return 0;
}

static bool is_checksum_file(const char *fn) {
        /* Returns true if the specified filename refers to a checksum file we grok */

        if (!fn)
                return false;

        return streq(fn, "SHA256SUMS") || endswith(fn, ".sha256");
}

static SignatureStyle signature_style_from_filename(const char *fn) {
        /* Returns true if the specified filename refers to a signature file we grok */

        if (!fn)
                return _SIGNATURE_STYLE_INVALID;

        if (streq(fn, "SHA256SUMS.gpg"))
                return SIGNATURE_GPG_PER_DIRECTORY;

        if (streq(fn, "SHA256SUMS.asc"))
                return SIGNATURE_ASC_PER_DIRECTORY;

        if (endswith(fn, ".sha256.gpg"))
                return SIGNATURE_GPG_PER_FILE;

        if (endswith(fn, ".sha256.asc"))
                return SIGNATURE_ASC_PER_FILE;

        return _SIGNATURE_STYLE_INVALID;
}

int pull_make_verification_jobs(
                PullJob **ret_checksum_job,
                PullJob **ret_signature_job,
                ImportVerify verify,
                const char *checksum, /* set if literal checksum verification is requested, in which case 'verify' is set to _IMPORT_VERIFY_INVALID */
                const char *url,
                CurlGlue *glue,
                PullJobFinished on_finished,
                void *userdata) {

        _cleanup_(pull_job_unrefp) PullJob *checksum_job = NULL, *signature_job = NULL;
        _cleanup_free_ char *fn = NULL;
        int r;

        assert(ret_checksum_job);
        assert(ret_signature_job);
        assert(verify == _IMPORT_VERIFY_INVALID || verify < _IMPORT_VERIFY_MAX);
        assert(verify == _IMPORT_VERIFY_INVALID || verify >= 0);
        assert((verify < 0) || !checksum);
        assert(url);
        assert(glue);

        /* If verification is turned off, or if the checksum to validate is already specified we don't need
         * to download a checksum file or signature, hence shortcut things */
        if (verify == IMPORT_VERIFY_NO || checksum) {
                *ret_checksum_job = *ret_signature_job = NULL;
                return 0;
        }

        r = import_url_last_component(url, &fn);
        if (r < 0 && r != -EADDRNOTAVAIL) /* EADDRNOTAVAIL means there was no last component, which is OK for
                                           * us, we'll just assume it's not a checksum/signature file */
                return r;

        /* Acquire the checksum file if verification or signature verification is requested and the main file
         * to acquire isn't a checksum or signature file anyway */
        if (verify != IMPORT_VERIFY_NO && !is_checksum_file(fn) && signature_style_from_filename(fn) < 0) {
                _cleanup_free_ char *checksum_url = NULL;
                const char *suffixed = NULL;

                /* Queue jobs for the checksum file for the image. */

                if (fn)
                        suffixed = strjoina(fn, ".sha256"); /* Start with the suse-style checksum (if there's a base filename) */
                else
                        suffixed = "SHA256SUMS";

                r = import_url_change_last_component(url, suffixed, &checksum_url);
                if (r < 0)
                        return r;

                r = pull_job_new(&checksum_job, checksum_url, glue, userdata);
                if (r < 0)
                        return r;

                checksum_job->on_finished = on_finished;
                checksum_job->uncompressed_max = checksum_job->compressed_max = 1ULL * 1024ULL * 1024ULL;
                checksum_job->on_not_found = pull_job_restart_with_sha256sum; /* if this fails, look for ubuntu-style checksum */
        }

        if (verify == IMPORT_VERIFY_SIGNATURE && signature_style_from_filename(fn) < 0) {
                _cleanup_free_ char *signature_url = NULL;
                const char *suffixed = NULL;

                if (fn)
                        suffixed = strjoina(fn, ".sha256.asc"); /* Start with the suse-style checksum (if there's a base filename) */
                else
                        suffixed = "SHA256SUMS.gpg";

                /* Queue job for the signature file for the image. */
                r = import_url_change_last_component(url, suffixed, &signature_url);
                if (r < 0)
                        return r;

                r = pull_job_new(&signature_job, signature_url, glue, userdata);
                if (r < 0)
                        return r;

                signature_job->on_finished = on_finished;
                signature_job->uncompressed_max = signature_job->compressed_max = 1ULL * 1024ULL * 1024ULL;
                signature_job->on_not_found = pull_job_restart_with_signature;
        }

        *ret_checksum_job = TAKE_PTR(checksum_job);
        *ret_signature_job = TAKE_PTR(signature_job);
        return 0;
}

static int verify_one(PullJob *checksum_job, PullJob *job) {
        _cleanup_free_ char *fn = NULL;
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
                return log_error_errno(r, "Failed to extract filename from URL '%s': %m", job->url);

        if (!filename_is_valid(fn))
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Cannot verify checksum, could not determine server-side file name.");

        if (is_checksum_file(fn) || signature_style_from_filename(fn) >= 0) /* We cannot verify checksum files or signature files with a checksum file */
                return log_error_errno(SYNTHETIC_ERRNO(ELOOP),
                                       "Cannot verify checksum/signature files via themselves.");

        const char *p = NULL;
        FOREACH_STRING(separator,
                       " *", /* separator for binary mode */
                       "  ", /* separator for text mode */
                       " "   /* non-standard separator used by linuxcontainers.org */) {
                _cleanup_free_ char *line = NULL;

                line = strjoin(job->checksum, separator, fn, "\n");
                if (!line)
                        return log_oom();

                p = memmem_safe(checksum_job->payload,
                                checksum_job->payload_size,
                                line,
                                strlen(line));
                if (p)
                        break;
        }

        /* Only counts if found at beginning of a line */
        if (!p || (p != (char*) checksum_job->payload && p[-1] != '\n'))
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "DOWNLOAD INVALID: Checksum of %s file did not check out, file has been tampered with.", fn);

        log_info("SHA256 checksum of %s is valid.", job->url);
        return 1;
}

static int verify_gpg(
                const void *payload, size_t payload_size,
                const void *signature, size_t signature_size) {

        _cleanup_close_pair_ int gpg_pipe[2] = EBADF_PAIR;
        _cleanup_(rm_rf_physical_and_freep) char *gpg_home = NULL;
        char sig_file_path[] = "/tmp/sigXXXXXX";
        _cleanup_(sigkill_waitp) pid_t pid = 0;
        int r;

        assert(payload || payload_size == 0);
        assert(signature || signature_size == 0);

        r = pipe2(gpg_pipe, O_CLOEXEC);
        if (r < 0)
                return log_error_errno(errno, "Failed to create pipe for gpg: %m");

        if (signature_size > 0) {
                _cleanup_close_ int sig_file = -EBADF;

                sig_file = mkostemp(sig_file_path, O_RDWR);
                if (sig_file < 0)
                        return log_error_errno(errno, "Failed to create temporary file: %m");

                r = loop_write(sig_file, signature, signature_size);
                if (r < 0) {
                        log_error_errno(r, "Failed to write to temporary file: %m");
                        goto finish;
                }
        }

        r = mkdtemp_malloc("/tmp/gpghomeXXXXXX", &gpg_home);
        if (r < 0) {
                log_error_errno(r, "Failed to create temporary home for gpg: %m");
                goto finish;
        }

        r = safe_fork_full("(gpg)",
                           (int[]) { gpg_pipe[0], -EBADF, STDERR_FILENO },
                           NULL, 0,
                           FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_REARRANGE_STDIO|FORK_LOG|FORK_RLIMIT_NOFILE_SAFE,
                           &pid);
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
                size_t k = ELEMENTSOF(cmd) - 6;

                /* Child */

                cmd[k++] = strjoina("--homedir=", gpg_home);

                /* We add the user keyring only to the command line arguments, if it's around since gpg fails
                 * otherwise. */
                if (access(USER_KEYRING_PATH, F_OK) >= 0)
                        cmd[k++] = "--keyring=" USER_KEYRING_PATH;
                else if (access(USER_KEYRING_PATH_LEGACY, F_OK) >= 0)
                        cmd[k++] = "--keyring=" USER_KEYRING_PATH_LEGACY;
                else
                        cmd[k++] = "--keyring=" VENDOR_KEYRING_PATH;

                cmd[k++] = "--verify";
                if (signature) {
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

        r = loop_write(gpg_pipe[1], payload, payload_size);
        if (r < 0) {
                log_error_errno(r, "Failed to write to pipe: %m");
                goto finish;
        }

        gpg_pipe[1] = safe_close(gpg_pipe[1]);

        r = wait_for_terminate_and_check("gpg", TAKE_PID(pid), WAIT_LOG_ABNORMAL);
        if (r < 0)
                goto finish;
        if (r != EXIT_SUCCESS)
                r = log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                    "DOWNLOAD INVALID: Signature verification failed.");
        else {
                log_info("Signature verification succeeded.");
                r = 0;
        }

finish:
        if (signature_size > 0)
                (void) unlink(sig_file_path);

        return r;
}

int pull_verify(ImportVerify verify,
                const char *checksum, /* Verify with literal checksum */
                PullJob *main_job,
                PullJob *checksum_job,
                PullJob *signature_job,
                PullJob *settings_job,
                PullJob *roothash_job,
                PullJob *roothash_signature_job,
                PullJob *verity_job) {

        _cleanup_free_ char *fn = NULL;
        VerificationStyle style;
        PullJob *verify_job;
        int r;

        assert(verify == _IMPORT_VERIFY_INVALID || verify < _IMPORT_VERIFY_MAX);
        assert(verify == _IMPORT_VERIFY_INVALID || verify >= 0);
        assert((verify < 0) || !checksum);
        assert(main_job);
        assert(main_job->state == PULL_JOB_DONE);

        if (verify == IMPORT_VERIFY_NO) /* verification turned off */
                return 0;

        if (checksum) {
                /* Verification by literal checksum */
                assert(!checksum_job);
                assert(!signature_job);
                assert(!settings_job);
                assert(!roothash_job);
                assert(!roothash_signature_job);
                assert(!verity_job);

                assert(main_job->calc_checksum);
                assert(main_job->checksum);

                if (!strcaseeq(checksum, main_job->checksum))
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "DOWNLOAD INVALID: Checksum of %s file did not check out, file has been tampered with.",
                                               main_job->url);

                return 0;
        }

        r = import_url_last_component(main_job->url, &fn);
        if (r < 0)
                return log_error_errno(r, "Failed to extract filename from URL '%s': %m", main_job->url);

        if (signature_style_from_filename(fn) >= 0)
                return log_error_errno(SYNTHETIC_ERRNO(ELOOP),
                                       "Main download is a signature file, can't verify it.");

        if (is_checksum_file(fn)) {
                log_debug("Main download is a checksum file, can't validate its checksum with itself, skipping.");
                verify_job = main_job;
        } else {
                assert(main_job->calc_checksum);
                assert(main_job->checksum);
                assert(checksum_job);
                assert(checksum_job->state == PULL_JOB_DONE);

                if (!checksum_job->payload || checksum_job->payload_size <= 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "Checksum is empty, cannot verify.");

                PullJob *j;
                FOREACH_ARGUMENT(j, main_job, settings_job, roothash_job, roothash_signature_job, verity_job) {
                        r = verify_one(checksum_job, j);
                        if (r < 0)
                                return r;
                }

                verify_job = checksum_job;
        }

        if (verify != IMPORT_VERIFY_SIGNATURE)
                return 0;

        assert(verify_job);

        r = verification_style_from_url(verify_job->url, &style);
        if (r < 0)
                return log_error_errno(r, "Failed to determine verification style from URL '%s': %m", verify_job->url);

        assert(signature_job);
        assert(signature_job->state == PULL_JOB_DONE);

        if (!signature_job->payload || signature_job->payload_size <= 0)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Signature is empty, cannot verify.");

        return verify_gpg(verify_job->payload, verify_job->payload_size, signature_job->payload, signature_job->payload_size);
}

int verification_style_from_url(const char *url, VerificationStyle *ret) {
        _cleanup_free_ char *last = NULL;
        int r;

        assert(url);
        assert(ret);

        /* Determines which kind of verification style is appropriate for this url */

        r = import_url_last_component(url, &last);
        if (r < 0)
                return r;

        if (streq(last, "SHA256SUMS")) {
                *ret = VERIFICATION_PER_DIRECTORY;
                return 0;
        }

        if (endswith(last, ".sha256")) {
                *ret = VERIFICATION_PER_FILE;
                return 0;
        }

        return -EINVAL;
}

int pull_job_restart_with_sha256sum(PullJob *j, char **ret) {
        VerificationStyle style;
        int r;

        assert(j);

        /* Generic implementation of a PullJobNotFound handler, that restarts the job requesting SHA256SUMS */

        r = verification_style_from_url(j->url, &style);
        if (r < 0)
                return log_error_errno(r, "Failed to determine verification style of URL '%s': %m", j->url);

        if (style == VERIFICATION_PER_DIRECTORY) { /* Nothing to do anymore */
                *ret = NULL;
                return 0;
        }

        assert(style == VERIFICATION_PER_FILE); /* This must have been .sha256 style URL before */

        log_debug("Got 404 for '%s', now trying to get SHA256SUMS instead.", j->url);

        r = import_url_change_last_component(j->url, "SHA256SUMS", ret);
        if (r < 0)
                return log_error_errno(r, "Failed to replace SHA256SUMS suffix: %m");

        return 1;
}

int signature_style_from_url(const char *url, SignatureStyle *ret, char **ret_filename) {
        _cleanup_free_ char *last = NULL;
        SignatureStyle style;
        int r;

        assert(url);
        assert(ret);
        assert(ret_filename);

        /* Determines which kind of signature style is appropriate for this url */

        r = import_url_last_component(url, &last);
        if (r < 0)
                return r;

        style = signature_style_from_filename(last);
        if (style < 0)
                return style;

        *ret_filename = TAKE_PTR(last);
        *ret = style;
        return 0;
}

int pull_job_restart_with_signature(PullJob *j, char **ret) {
        _cleanup_free_ char *last = NULL;
        SignatureStyle style;
        int r;

        assert(j);

        /* Generic implementation of a PullJobNotFound handler, that restarts the job requesting a different
         * signature file. After the initial file, additional *.sha256.gpg, SHA256SUMS.gpg and SHA256SUMS.asc
         * are tried in this order. */

        r = signature_style_from_url(j->url, &style, &last);
        if (r < 0)
                return log_error_errno(r, "Failed to determine signature style of URL '%s': %m", j->url);

        switch (style) {

        case SIGNATURE_ASC_PER_DIRECTORY: /* Nothing to do anymore */
                *ret = NULL;
                return 0;

        case SIGNATURE_ASC_PER_FILE: { /* Try .sha256.gpg next */
                char *ext;

                log_debug("Got 404 for '%s', now trying to get .sha256.gpg instead.", j->url);

                ext = endswith(last, ".asc");
                assert(ext);
                strcpy(ext, ".gpg");

                r = import_url_change_last_component(j->url, last, ret);
                if (r < 0)
                        return log_error_errno(r, "Failed to replace .sha256.asc suffix: %m");
                break;
        }

        case SIGNATURE_GPG_PER_FILE: /* Try SHA256SUMS.gpg next */
                log_debug("Got 404 for '%s', now trying to get SHA256SUMS.gpg instead.", j->url);
                r = import_url_change_last_component(j->url, "SHA256SUMS.gpg", ret);
                if (r < 0)
                        return log_error_errno(r, "Failed to replace SHA256SUMS suffix: %m");
                break;

        case SIGNATURE_GPG_PER_DIRECTORY:
                log_debug("Got 404 for '%s', now trying to get SHA256SUMS.asc instead.", j->url);
                r = import_url_change_last_component(j->url, "SHA256SUMS.asc", ret);
                if (r < 0)
                        return log_error_errno(r, "Failed to replace SHA256SUMS.gpg suffix: %m");
                break;

        default:
                assert_not_reached();
        }

        return 1;
}

bool pull_validate_local(const char *name, ImportFlags flags) {

        if (FLAGS_SET(flags, IMPORT_DIRECT))
                return path_is_valid(name);

        return image_name_is_valid(name);
}

int pull_url_needs_checksum(const char *url) {
        _cleanup_free_ char *fn = NULL;
        int r;

        /* Returns true if we need to validate this resource via a hash value. This returns true for all
         * files — except for gpg signature files and SHA256SUMS files and the like, which are validated with
         * a validation tool like gpg. */

        r = import_url_last_component(url, &fn);
        if (r == -EADDRNOTAVAIL) /* no last component? then let's assume it's not a signature/checksum file */
                return false;
        if (r < 0)
                return r;

        return !is_checksum_file(fn) && signature_style_from_filename(fn) < 0;
}
