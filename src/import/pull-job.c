/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/xattr.h>

#include "alloc-util.h"
#include "curl-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "hexdecoct.h"
#include "io-util.h"
#include "log.h"
#include "parse-util.h"
#include "pull-common.h"
#include "pull-job.h"
#include "string-util.h"
#include "strv.h"
#include "sync-util.h"
#include "time-util.h"
#include "xattr-util.h"

static int http_status_ok(CURLcode status) {
        /* Consider all HTTP status code in the 2xx range as OK */
        return status >= 200 && status <= 299;
}

static int http_status_etag_exists(CURLcode status) {
        /* This one is special, it's triggered by our etag mgmt logic */
        return status == 304;
}

void pull_job_close_disk_fd(PullJob *j) {
        if (!j)
                return;

        if (j->close_disk_fd)
                safe_close(j->disk_fd);

        j->disk_fd = -EBADF;
}

PullJob* pull_job_unref(PullJob *j) {
        if (!j)
                return NULL;

        pull_job_close_disk_fd(j);

        curl_glue_remove_and_free(j->glue, j->curl);
        curl_slist_free_all(j->request_header);

        import_compress_free(&j->compress);

        if (j->checksum_ctx)
                EVP_MD_CTX_free(j->checksum_ctx);

        free(j->url);
        free(j->etag);
        strv_free(j->old_etags);
        iovec_done(&j->payload);
        iovec_done(&j->checksum);
        iovec_done(&j->expected_checksum);
        free(j->content_type);

        if (j->free_userdata)
                j->free_userdata(j->userdata);

        return mfree(j);
}

static void pull_job_finish(PullJob *j, int ret) {
        assert(j);

        if (IN_SET(j->state, PULL_JOB_DONE, PULL_JOB_FAILED))
                return;

        if (ret == 0) {
                j->state = PULL_JOB_DONE;
                j->progress_percent = 100;
                log_info("Download of %s complete.", j->url);
        } else {
                j->state = PULL_JOB_FAILED;
                j->error = ret;
        }

        if (j->on_finished)
                j->on_finished(j);
}

static int pull_job_restart(PullJob *j, const char *new_url) {
        int r;

        assert(j);
        assert(new_url);

        r = free_and_strdup(&j->url, new_url);
        if (r < 0)
                return r;

        j->state = PULL_JOB_INIT;
        j->error = 0;
        iovec_done(&j->payload);
        j->written_compressed = 0;
        j->written_uncompressed = 0;
        j->content_length = UINT64_MAX;
        j->etag = mfree(j->etag);
        j->etag_exists = false;
        j->mtime = 0;
        iovec_done(&j->checksum);
        iovec_done(&j->expected_checksum);
        j->expected_content_length = UINT64_MAX;
        j->content_type = mfree(j->content_type);

        curl_glue_remove_and_free(j->glue, j->curl);
        j->curl = NULL;

        curl_slist_free_all(j->request_header);
        j->request_header = NULL;

        import_compress_free(&j->compress);

        if (j->checksum_ctx) {
                EVP_MD_CTX_free(j->checksum_ctx);
                j->checksum_ctx = NULL;
        }

        r = pull_job_begin(j);
        if (r < 0)
                return r;

        return 0;
}

static uint64_t pull_job_content_length_effective(PullJob *j) {
        assert(j);

        if (j->expected_content_length != UINT64_MAX)
                return j->expected_content_length;

        return j->content_length;
}

void pull_job_curl_on_finished(CurlGlue *g, CURL *curl, CURLcode result) {
        PullJob *j = NULL;
        char *scheme = NULL;
        CURLcode code;
        int r;

        if (curl_easy_getinfo(curl, CURLINFO_PRIVATE, (char **)&j) != CURLE_OK)
                return;

        if (!j || IN_SET(j->state, PULL_JOB_DONE, PULL_JOB_FAILED))
                return;

        code = curl_easy_getinfo(curl, CURLINFO_SCHEME, &scheme);
        if (code != CURLE_OK || !scheme) {
                r = log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to retrieve URL scheme.");
                goto finish;
        }

        if (strcaseeq(scheme, "FILE") && result == CURLE_FILE_COULDNT_READ_FILE && j->on_not_found) {
                _cleanup_free_ char *new_url = NULL;

                /* This resource wasn't found, but the implementer wants to maybe let us know a new URL, query for it. */
                r = j->on_not_found(j, &new_url);
                if (r < 0)
                        goto finish;
                if (r > 0) { /* A new url to use */
                        assert(new_url);

                        r = pull_job_restart(j, new_url);
                        if (r < 0)
                                goto finish;

                        return;
                }

                /* if this didn't work, handle like any other error below */
        }

        if (result != CURLE_OK) {
                r = log_error_errno(SYNTHETIC_ERRNO(EIO), "Transfer failed: %s", curl_easy_strerror(result));
                goto finish;
        }

        if (STRCASE_IN_SET(scheme, "HTTP", "HTTPS")) {
                long status;

                code = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
                if (code != CURLE_OK) {
                        r = log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to retrieve response code: %s", curl_easy_strerror(code));
                        goto finish;
                }

                if (http_status_etag_exists(status)) {
                        log_info("Image already downloaded. Skipping download.");
                        j->etag_exists = true;
                        r = 0;
                        goto finish;
                } else if (status >= 300) {

                        if (status == 404 && j->on_not_found) {
                                _cleanup_free_ char *new_url = NULL;

                                /* This resource wasn't found, but the implementer wants to maybe let us know a new URL, query for it. */
                                r = j->on_not_found(j, &new_url);
                                if (r < 0)
                                        goto finish;

                                if (r > 0) { /* A new url to use */
                                        assert(new_url);

                                        r = pull_job_restart(j, new_url);
                                        if (r < 0)
                                                goto finish;

                                        code = curl_easy_getinfo(j->curl, CURLINFO_RESPONSE_CODE, &status);
                                        if (code != CURLE_OK) {
                                                r = log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to retrieve response code: %s", curl_easy_strerror(code));
                                                goto finish;
                                        }

                                        if (status == 0)
                                                return;
                                }
                        }

                        r = log_notice_errno(
                                        status == 404 ? SYNTHETIC_ERRNO(ENOMEDIUM) : SYNTHETIC_ERRNO(EIO), /* Make the most common error recognizable */
                                        "HTTP request to %s failed with code %li.", j->url, status);
                        goto finish;
                } else if (status < 200) {
                        r = log_error_errno(SYNTHETIC_ERRNO(EIO), "HTTP request to %s finished with unexpected code %li.", j->url, status);
                        goto finish;
                }
        }

        if (j->state != PULL_JOB_RUNNING) {
                r = log_error_errno(SYNTHETIC_ERRNO(EIO), "Premature connection termination.");
                goto finish;
        }

        uint64_t cl = pull_job_content_length_effective(j);
        if (cl != UINT64_MAX &&
            cl != j->written_compressed) {
                r = log_error_errno(SYNTHETIC_ERRNO(EIO), "Download truncated.");
                goto finish;
        }

        if (j->checksum_ctx) {
                unsigned checksum_len;

                iovec_done(&j->checksum);
                j->checksum.iov_base = malloc(EVP_MAX_MD_SIZE);
                if (!j->checksum.iov_base) {
                        r = log_oom();
                        goto finish;
                }

                r = EVP_DigestFinal_ex(j->checksum_ctx, j->checksum.iov_base, &checksum_len);
                if (r == 0) {
                        r = log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to get checksum.");
                        goto finish;
                }
                assert(checksum_len <= EVP_MAX_MD_SIZE);
                j->checksum.iov_len = checksum_len;

                if (DEBUG_LOGGING) {
                        _cleanup_free_ char *h = hexmem(j->checksum.iov_base, j->checksum.iov_len);
                        if (!h) {
                                r = log_oom();
                                goto finish;
                        }

                        log_debug("%s of %s is %s.", EVP_MD_CTX_get0_name(j->checksum_ctx), j->url, h);
                }

                if (iovec_is_set(&j->expected_checksum) &&
                    iovec_memcmp(&j->checksum, &j->expected_checksum) != 0) {
                        r = log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Checksum of downloaded resource does not match expected checksum, yikes.");
                        goto finish;
                }
        }

        /* Do a couple of finishing disk operations, but only if we are the sole owner of the file (i.e. no
         * offset is specified, which indicates we only own the file partially) */

        if (j->disk_fd >= 0) {

                if (S_ISREG(j->disk_stat.st_mode)) {

                        if (j->offset == UINT64_MAX) {

                                if (j->written_compressed > 0) {
                                        /* Make sure the file size is right, in case the file was sparse and
                                         * we just moved to the last part. */
                                        if (ftruncate(j->disk_fd, j->written_uncompressed) < 0) {
                                                r = log_error_errno(errno, "Failed to truncate file: %m");
                                                goto finish;
                                        }
                                }

                                if (j->etag)
                                        (void) fsetxattr(j->disk_fd, "user.source_etag", j->etag, strlen(j->etag), 0);
                                if (j->url)
                                        (void) fsetxattr(j->disk_fd, "user.source_url", j->url, strlen(j->url), 0);

                                if (j->mtime != 0) {
                                        struct timespec ut;

                                        timespec_store(&ut, j->mtime);

                                        if (futimens(j->disk_fd, (struct timespec[]) { ut, ut }) < 0)
                                                log_debug_errno(errno, "Failed to adjust atime/mtime of created image, ignoring: %m");

                                        r = fd_setcrtime(j->disk_fd, j->mtime);
                                        if (r < 0)
                                                log_debug_errno(r, "Failed to adjust crtime of created image, ignoring: %m");
                                }
                        }

                        if (j->sync) {
                                r = fsync_full(j->disk_fd);
                                if (r < 0) {
                                        log_error_errno(r, "Failed to synchronize file to disk: %m");
                                        goto finish;
                                }
                        }

                } else if (S_ISBLK(j->disk_stat.st_mode) && j->sync) {

                        if (fsync(j->disk_fd) < 0) {
                                r = log_error_errno(errno, "Failed to synchronize block device: %m");
                                goto finish;
                        }
                }
        }

        log_info("Acquired %s.", FORMAT_BYTES(j->written_uncompressed));

        r = 0;

finish:
        pull_job_finish(j, r);
}

static int pull_job_write_uncompressed(const void *p, size_t sz, void *userdata) {
        PullJob *j = ASSERT_PTR(userdata);
        bool too_much = false;
        int r;

        assert(p);
        assert(sz > 0);

        if (j->written_uncompressed > UINT64_MAX - sz)
                return log_error_errno(SYNTHETIC_ERRNO(EOVERFLOW), "File too large, overflow");

        if (j->written_uncompressed >= j->uncompressed_max) {
                too_much = true;
                goto finish;
        }

        if (j->written_uncompressed + sz > j->uncompressed_max) {
                too_much = true;
                sz = j->uncompressed_max - j->written_uncompressed; /* since we have the data in memory
                                                                     * already, we might as well write it to
                                                                     * disk to the max */
        }

        if (j->disk_fd >= 0) {

                if (S_ISREG(j->disk_stat.st_mode) && j->offset == UINT64_MAX) {
                        ssize_t n;

                        n = sparse_write(j->disk_fd, p, sz, 64);
                        if (n < 0)
                                return log_error_errno((int) n, "Failed to write file: %m");
                        if ((size_t) n < sz)
                                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Short write");
                } else {
                        r = loop_write(j->disk_fd, p, sz);
                        if (r < 0)
                                return log_error_errno(r, "Failed to write file: %m");
                }
        }

        if (j->disk_fd < 0 || j->force_memory) {
                uint8_t *a = j->payload.iov_base;

                if (!GREEDY_REALLOC(a, j->payload.iov_len + sz + 1))
                        return log_oom();

                *((uint8_t*) mempcpy(a + j->payload.iov_len, p, sz)) = 0;
                j->payload.iov_base = a;
                j->payload.iov_len += sz;
        }

        j->written_uncompressed += sz;

finish:
        if (too_much)
                return log_error_errno(SYNTHETIC_ERRNO(EFBIG), "File overly large, refusing.");

        return 0;
}

static int pull_job_write_compressed(PullJob *j, const struct iovec *data) {
        int r;

        assert(j);
        assert(iovec_is_valid(data));

        if (!iovec_is_set(data))
                return 0;

        if (j->written_compressed + data->iov_len < j->written_compressed)
                return log_error_errno(SYNTHETIC_ERRNO(EOVERFLOW), "File too large, overflow");

        if (j->written_compressed + data->iov_len > j->compressed_max)
                return log_error_errno(SYNTHETIC_ERRNO(EFBIG), "File overly large, refusing.");

        uint64_t cl = pull_job_content_length_effective(j);
        if (cl != UINT64_MAX &&
            j->written_compressed + data->iov_len > cl)
                return log_error_errno(SYNTHETIC_ERRNO(EFBIG),
                                       "Content length incorrect.");

        if (j->checksum_ctx) {
                r = EVP_DigestUpdate(j->checksum_ctx, data->iov_base, data->iov_len);
                if (r == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                               "Could not hash chunk.");
        }

        r = import_uncompress(&j->compress, data->iov_base, data->iov_len, pull_job_write_uncompressed, j);
        if (r < 0)
                return r;

        j->written_compressed += data->iov_len;

        return 0;
}

static int pull_job_open_disk(PullJob *j) {
        int r;

        assert(j);

        if (j->on_open_disk) {
                r = j->on_open_disk(j);
                if (r < 0)
                        return r;
        }

        if (j->disk_fd >= 0) {
                if (fstat(j->disk_fd, &j->disk_stat) < 0)
                        return log_error_errno(errno, "Failed to stat disk file: %m");

                if (j->offset != UINT64_MAX) {
                        if (lseek(j->disk_fd, j->offset, SEEK_SET) < 0)
                                return log_error_errno(errno, "Failed to seek on file descriptor: %m");
                }
        }

        if (j->calc_checksum) {
                j->checksum_ctx = EVP_MD_CTX_new();
                if (!j->checksum_ctx)
                        return log_oom();

                r = EVP_DigestInit_ex(j->checksum_ctx, EVP_sha256(), NULL);
                if (r == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                               "Failed to initialize hash context.");
        }

        return 0;
}

static int pull_job_detect_compression(PullJob *j) {
        int r;

        assert(j);

        r = import_uncompress_detect(&j->compress, j->payload.iov_base, j->payload.iov_len);
        if (r < 0)
                return log_error_errno(r, "Failed to initialize compressor: %m");
        if (r == 0)
                return 0;

        log_debug("Stream is compressed: %s", import_compress_type_to_string(j->compress.type));

        r = pull_job_open_disk(j);
        if (r < 0)
                return r;

        /* Now, take the payload we read so far, and decompress it */
        _cleanup_(iovec_done) struct iovec stub = TAKE_STRUCT(j->payload);

        j->state = PULL_JOB_RUNNING;

        r = pull_job_write_compressed(j, &stub);
        if (r < 0)
                return r;

        return 0;
}

static size_t pull_job_write_callback(void *contents, size_t size, size_t nmemb, void *userdata) {
        PullJob *j = ASSERT_PTR(userdata);
        size_t sz = size * nmemb;
        int r;

        assert(contents);

        switch (j->state) {

        case PULL_JOB_ANALYZING:
                /* Let's first check what it actually is */
                if (!iovec_append(&j->payload, &IOVEC_MAKE(contents, sz))) {
                        r = log_oom();
                        goto fail;
                }

                r = pull_job_detect_compression(j);
                if (r < 0)
                        goto fail;

                break;

        case PULL_JOB_RUNNING:
                r = pull_job_write_compressed(j, &IOVEC_MAKE(contents, sz));
                if (r < 0)
                        goto fail;

                break;

        case PULL_JOB_DONE:
        case PULL_JOB_FAILED:
                r = -ESTALE;
                goto fail;

        default:
                assert_not_reached();
        }

        return sz;

fail:
        pull_job_finish(j, r);
        return 0;
}

static size_t pull_job_header_callback(void *contents, size_t size, size_t nmemb, void *userdata) {
        _cleanup_free_ char *length = NULL, *last_modified = NULL, *etag = NULL, *ct = NULL;
        size_t sz = size * nmemb;
        PullJob *j = ASSERT_PTR(userdata);
        CURLcode code;
        long status;
        int r;

        assert(contents);

        if (IN_SET(j->state, PULL_JOB_DONE, PULL_JOB_FAILED)) {
                r = -ESTALE;
                goto fail;
        }

        assert(j->state == PULL_JOB_ANALYZING);

        code = curl_easy_getinfo(j->curl, CURLINFO_RESPONSE_CODE, &status);
        if (code != CURLE_OK) {
                r = log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to retrieve response code: %s", curl_easy_strerror(code));
                goto fail;
        }

        if (http_status_ok(status) || http_status_etag_exists(status)) {
                /* Check Etag on OK and etag exists responses. */

                r = curl_header_strdup(contents, sz, "ETag:", &etag);
                if (r < 0) {
                        log_oom();
                        goto fail;
                }
                if (r > 0) {
                        free_and_replace(j->etag, etag);

                        if (strv_contains(j->old_etags, j->etag)) {
                                log_info("Image already downloaded. Skipping download. (%s)", j->etag);
                                j->etag_exists = true;
                                pull_job_finish(j, 0);
                                return sz;
                        }

                        return sz;
                }
        }

        if (!http_status_ok(status)) /* Let's ignore the rest here, these requests are probably redirects and
                                      * stuff where the headers aren't interesting to us */
                return sz;

        r = curl_header_strdup(contents, sz, "Content-Length:", &length);
        if (r < 0) {
                log_oom();
                goto fail;
        }
        if (r > 0) {
                (void) safe_atou64(length, &j->content_length);

                if (j->content_length != UINT64_MAX) {
                        if (j->content_length > j->compressed_max) {
                                r = log_error_errno(SYNTHETIC_ERRNO(EFBIG), "Content too large.");
                                goto fail;
                        }

                        if (j->expected_content_length != UINT64_MAX &&
                            j->expected_content_length != j->content_length) {
                                r = log_error_errno(SYNTHETIC_ERRNO(EPROTO), "Content does not have expected size.");
                                goto fail;
                        }

                        log_info("Downloading %s for %s.", FORMAT_BYTES(j->content_length), j->url);
                }

                return sz;
        }

        r = curl_header_strdup(contents, sz, "Last-Modified:", &last_modified);
        if (r < 0) {
                log_oom();
                goto fail;
        }
        if (r > 0) {
                (void) curl_parse_http_time(last_modified, &j->mtime);
                return sz;
        }

        r = curl_header_strdup(contents, sz, "Content-Type:", &ct);
        if (r < 0) {
                log_oom();
                goto fail;
        }
        if (r > 0) {
                free_and_replace(j->content_type, ct);
                return sz;
        }

        if (j->on_header) {
                r = j->on_header(j, contents, sz);
                if (r < 0)
                        goto fail;
        }

        return sz;

fail:
        pull_job_finish(j, r);
        return 0;
}

static int pull_job_progress_callback(void *userdata, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow) {
        PullJob *j = ASSERT_PTR(userdata);
        unsigned percent;
        usec_t n;

        if (dltotal <= 0)
                return 0;

        percent = ((100 * dlnow) / dltotal);
        n = now(CLOCK_MONOTONIC);

        if (n > j->last_status_usec + USEC_PER_SEC &&
            percent != j->progress_percent &&
            dlnow < dltotal) {

                if (n - j->start_usec > USEC_PER_SEC && dlnow > 0) {
                        usec_t left, done;

                        done = n - j->start_usec;
                        left = (usec_t) (((double) done * (double) dltotal) / dlnow) - done;

                        log_info("Got %u%% of %s. %s left at %s/s.",
                                 percent,
                                 j->url,
                                 FORMAT_TIMESPAN(left, USEC_PER_SEC),
                                 FORMAT_BYTES((uint64_t) ((double) dlnow / ((double) done / (double) USEC_PER_SEC))));
                } else
                        log_info("Got %u%% of %s.", percent, j->url);

                j->progress_percent = percent;
                j->last_status_usec = n;

                if (j->on_progress)
                        j->on_progress(j);
        }

        return 0;
}

int pull_job_new(
                PullJob **ret,
                const char *url,
                CurlGlue *glue,
                void *userdata) {

        _cleanup_(pull_job_unrefp) PullJob *j = NULL;
        _cleanup_free_ char *u = NULL;

        assert(url);
        assert(glue);
        assert(ret);

        u = strdup(url);
        if (!u)
                return -ENOMEM;

        j = new(PullJob, 1);
        if (!j)
                return -ENOMEM;

        *j = (PullJob) {
                .state = PULL_JOB_INIT,
                .disk_fd = -EBADF,
                .close_disk_fd = true,
                .userdata = userdata,
                .glue = glue,
                .content_length = UINT64_MAX,
                .start_usec = now(CLOCK_MONOTONIC),
                .compressed_max = 64LLU * 1024LLU * 1024LLU * 1024LLU, /* 64GB safety limit */
                .uncompressed_max = 64LLU * 1024LLU * 1024LLU * 1024LLU, /* 64GB safety limit */
                .url = TAKE_PTR(u),
                .offset = UINT64_MAX,
                .sync = true,
                .expected_content_length = UINT64_MAX,
        };

        *ret = TAKE_PTR(j);

        return 0;
}

int pull_job_add_request_header(PullJob *j, const char *hdr) {
        assert(j);
        assert(hdr);

        if (j->request_header) {
                struct curl_slist *l;

                l = curl_slist_append(j->request_header, hdr);
                if (!l)
                        return -ENOMEM;

                j->request_header = l;
        } else {
                j->request_header = curl_slist_new(hdr, NULL);
                if (!j->request_header)
                        return -ENOMEM;
        }

        return 0;
}

int pull_job_begin(PullJob *j) {
        int r;

        assert(j);

        if (j->state != PULL_JOB_INIT)
                return -EBUSY;

        r = curl_glue_make(&j->curl, j->url, j);
        if (r < 0)
                return r;

        if (!strv_isempty(j->old_etags)) {
                _cleanup_free_ char *cc = NULL, *hdr = NULL;

                cc = strv_join(j->old_etags, ", ");
                if (!cc)
                        return -ENOMEM;

                hdr = strjoin("If-None-Match: ", cc);
                if (!hdr)
                        return -ENOMEM;

                r = pull_job_add_request_header(j, hdr);
                if (r < 0)
                        return r;
        }

        if (j->request_header) {
                if (curl_easy_setopt(j->curl, CURLOPT_HTTPHEADER, j->request_header) != CURLE_OK)
                        return -EIO;
        }

        if (curl_easy_setopt(j->curl, CURLOPT_WRITEFUNCTION, pull_job_write_callback) != CURLE_OK)
                return -EIO;

        if (curl_easy_setopt(j->curl, CURLOPT_WRITEDATA, j) != CURLE_OK)
                return -EIO;

        if (curl_easy_setopt(j->curl, CURLOPT_HEADERFUNCTION, pull_job_header_callback) != CURLE_OK)
                return -EIO;

        if (curl_easy_setopt(j->curl, CURLOPT_HEADERDATA, j) != CURLE_OK)
                return -EIO;

        if (curl_easy_setopt(j->curl, CURLOPT_XFERINFOFUNCTION, pull_job_progress_callback) != CURLE_OK)
                return -EIO;

        if (curl_easy_setopt(j->curl, CURLOPT_XFERINFODATA, j) != CURLE_OK)
                return -EIO;

        if (curl_easy_setopt(j->curl, CURLOPT_NOPROGRESS, 0L) != CURLE_OK)
                return -EIO;

        r = curl_glue_add(j->glue, j->curl);
        if (r < 0)
                return r;

        j->state = PULL_JOB_ANALYZING;

        return 0;
}

int pull_job_set_accept(PullJob *j, char * const *l) {
        assert(j);

        if (strv_isempty(l))
                return 0;

        _cleanup_free_ char *joined = strv_join(l, ", ");
        if (!joined)
                return -ENOMEM;

        _cleanup_free_ char *f = strjoin("Accept: ", joined);
        if (!f)
                return -ENOMEM;

        return pull_job_add_request_header(j, f);
}
