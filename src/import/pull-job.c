/* SPDX-License-Identifier: LGPL-2.1+ */

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/xattr.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "gcrypt-util.h"
#include "hexdecoct.h"
#include "import-util.h"
#include "io-util.h"
#include "machine-pool.h"
#include "parse-util.h"
#include "pull-common.h"
#include "pull-job.h"
#include "string-util.h"
#include "strv.h"
#include "xattr-util.h"

PullJob* pull_job_unref(PullJob *j) {
        if (!j)
                return NULL;

        curl_glue_remove_and_free(j->glue, j->curl);
        curl_slist_free_all(j->request_header);

        safe_close(j->disk_fd);

        import_compress_free(&j->compress);

        if (j->checksum_context)
                gcry_md_close(j->checksum_context);

        free(j->url);
        free(j->etag);
        strv_free(j->old_etags);
        free(j->payload);
        free(j->checksum);

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

static int pull_job_restart(PullJob *j) {
        int r;
        char *chksum_url = NULL;

        r = import_url_change_last_component(j->url, "SHA256SUMS", &chksum_url);
        if (r < 0)
                return r;

        free(j->url);
        j->url = chksum_url;
        j->state = PULL_JOB_INIT;
        j->payload = mfree(j->payload);
        j->payload_size = 0;
        j->payload_allocated = 0;
        j->written_compressed = 0;
        j->written_uncompressed = 0;

        r = pull_job_begin(j);
        if (r < 0)
                return r;

        return 0;
}

void pull_job_curl_on_finished(CurlGlue *g, CURL *curl, CURLcode result) {
        PullJob *j = NULL;
        CURLcode code;
        long status;
        int r;

        if (curl_easy_getinfo(curl, CURLINFO_PRIVATE, (char **)&j) != CURLE_OK)
                return;

        if (!j || IN_SET(j->state, PULL_JOB_DONE, PULL_JOB_FAILED))
                return;

        if (result != CURLE_OK) {
                log_error("Transfer failed: %s", curl_easy_strerror(result));
                r = -EIO;
                goto finish;
        }

        code = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
        if (code != CURLE_OK) {
                log_error("Failed to retrieve response code: %s", curl_easy_strerror(code));
                r = -EIO;
                goto finish;
        } else if (status == 304) {
                log_info("Image already downloaded. Skipping download.");
                j->etag_exists = true;
                r = 0;
                goto finish;
        } else if (status >= 300) {
                if (status == 404 && j->style == VERIFICATION_PER_FILE) {

                        /* retry pull job with SHA256SUMS file */
                        r = pull_job_restart(j);
                        if (r < 0)
                                goto finish;

                        code = curl_easy_getinfo(j->curl, CURLINFO_RESPONSE_CODE, &status);
                        if (code != CURLE_OK) {
                                log_error("Failed to retrieve response code: %s", curl_easy_strerror(code));
                                r = -EIO;
                                goto finish;
                        }

                        if (status == 0) {
                                j->style = VERIFICATION_PER_DIRECTORY;
                                return;
                        }
                }

                log_error("HTTP request to %s failed with code %li.", j->url, status);
                r = -EIO;
                goto finish;
        } else if (status < 200) {
                log_error("HTTP request to %s finished with unexpected code %li.", j->url, status);
                r = -EIO;
                goto finish;
        }

        if (j->state != PULL_JOB_RUNNING) {
                log_error("Premature connection termination.");
                r = -EIO;
                goto finish;
        }

        if (j->content_length != (uint64_t) -1 &&
            j->content_length != j->written_compressed) {
                log_error("Download truncated.");
                r = -EIO;
                goto finish;
        }

        if (j->checksum_context) {
                uint8_t *k;

                k = gcry_md_read(j->checksum_context, GCRY_MD_SHA256);
                if (!k) {
                        log_error("Failed to get checksum.");
                        r = -EIO;
                        goto finish;
                }

                j->checksum = hexmem(k, gcry_md_get_algo_dlen(GCRY_MD_SHA256));
                if (!j->checksum) {
                        r = log_oom();
                        goto finish;
                }

                log_debug("SHA256 of %s is %s.", j->url, j->checksum);
        }

        if (j->disk_fd >= 0 && j->allow_sparse) {
                /* Make sure the file size is right, in case the file was
                 * sparse and we just seeked for the last part */

                if (ftruncate(j->disk_fd, j->written_uncompressed) < 0) {
                        r = log_error_errno(errno, "Failed to truncate file: %m");
                        goto finish;
                }

                if (j->etag)
                        (void) fsetxattr(j->disk_fd, "user.source_etag", j->etag, strlen(j->etag), 0);
                if (j->url)
                        (void) fsetxattr(j->disk_fd, "user.source_url", j->url, strlen(j->url), 0);

                if (j->mtime != 0) {
                        struct timespec ut[2];

                        timespec_store(&ut[0], j->mtime);
                        ut[1] = ut[0];
                        (void) futimens(j->disk_fd, ut);

                        (void) fd_setcrtime(j->disk_fd, j->mtime);
                }
        }

        r = 0;

finish:
        pull_job_finish(j, r);
}

static int pull_job_write_uncompressed(const void *p, size_t sz, void *userdata) {
        PullJob *j = userdata;
        ssize_t n;

        assert(j);
        assert(p);

        if (sz <= 0)
                return 0;

        if (j->written_uncompressed + sz < j->written_uncompressed)
                return log_error_errno(SYNTHETIC_ERRNO(EOVERFLOW),
                                       "File too large, overflow");

        if (j->written_uncompressed + sz > j->uncompressed_max)
                return log_error_errno(SYNTHETIC_ERRNO(EFBIG),
                                       "File overly large, refusing");

        if (j->disk_fd >= 0) {

                if (j->allow_sparse)
                        n = sparse_write(j->disk_fd, p, sz, 64);
                else {
                        n = write(j->disk_fd, p, sz);
                        if (n < 0)
                                n = -errno;
                }
                if (n < 0)
                        return log_error_errno((int) n, "Failed to write file: %m");
                if ((size_t) n < sz)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Short write");
        } else {

                if (!GREEDY_REALLOC(j->payload, j->payload_allocated, j->payload_size + sz))
                        return log_oom();

                memcpy(j->payload + j->payload_size, p, sz);
                j->payload_size += sz;
        }

        j->written_uncompressed += sz;

        return 0;
}

static int pull_job_write_compressed(PullJob *j, void *p, size_t sz) {
        int r;

        assert(j);
        assert(p);

        if (sz <= 0)
                return 0;

        if (j->written_compressed + sz < j->written_compressed)
                return log_error_errno(SYNTHETIC_ERRNO(EOVERFLOW), "File too large, overflow");

        if (j->written_compressed + sz > j->compressed_max)
                return log_error_errno(SYNTHETIC_ERRNO(EFBIG), "File overly large, refusing.");

        if (j->content_length != (uint64_t) -1 &&
            j->written_compressed + sz > j->content_length)
                return log_error_errno(SYNTHETIC_ERRNO(EFBIG),
                                       "Content length incorrect.");

        if (j->checksum_context)
                gcry_md_write(j->checksum_context, p, sz);

        r = import_uncompress(&j->compress, p, sz, pull_job_write_uncompressed, j);
        if (r < 0)
                return r;

        j->written_compressed += sz;

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
                /* Check if we can do sparse files */

                if (lseek(j->disk_fd, SEEK_SET, 0) == 0)
                        j->allow_sparse = true;
                else {
                        if (errno != ESPIPE)
                                return log_error_errno(errno, "Failed to seek on file descriptor: %m");

                        j->allow_sparse = false;
                }
        }

        if (j->calc_checksum) {
                initialize_libgcrypt(false);

                if (gcry_md_open(&j->checksum_context, GCRY_MD_SHA256, 0) != 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                               "Failed to initialize hash context.");
        }

        return 0;
}

static int pull_job_detect_compression(PullJob *j) {
        _cleanup_free_ uint8_t *stub = NULL;
        size_t stub_size;

        int r;

        assert(j);

        r = import_uncompress_detect(&j->compress, j->payload, j->payload_size);
        if (r < 0)
                return log_error_errno(r, "Failed to initialize compressor: %m");
        if (r == 0)
                return 0;

        log_debug("Stream is compressed: %s", import_compress_type_to_string(j->compress.type));

        r = pull_job_open_disk(j);
        if (r < 0)
                return r;

        /* Now, take the payload we read so far, and decompress it */
        stub = j->payload;
        stub_size = j->payload_size;

        j->payload = NULL;
        j->payload_size = 0;
        j->payload_allocated = 0;

        j->state = PULL_JOB_RUNNING;

        r = pull_job_write_compressed(j, stub, stub_size);
        if (r < 0)
                return r;

        return 0;
}

static size_t pull_job_write_callback(void *contents, size_t size, size_t nmemb, void *userdata) {
        PullJob *j = userdata;
        size_t sz = size * nmemb;
        int r;

        assert(contents);
        assert(j);

        switch (j->state) {

        case PULL_JOB_ANALYZING:
                /* Let's first check what it actually is */

                if (!GREEDY_REALLOC(j->payload, j->payload_allocated, j->payload_size + sz)) {
                        r = log_oom();
                        goto fail;
                }

                memcpy(j->payload + j->payload_size, contents, sz);
                j->payload_size += sz;

                r = pull_job_detect_compression(j);
                if (r < 0)
                        goto fail;

                break;

        case PULL_JOB_RUNNING:

                r = pull_job_write_compressed(j, contents, sz);
                if (r < 0)
                        goto fail;

                break;

        case PULL_JOB_DONE:
        case PULL_JOB_FAILED:
                r = -ESTALE;
                goto fail;

        default:
                assert_not_reached("Impossible state.");
        }

        return sz;

fail:
        pull_job_finish(j, r);
        return 0;
}

static size_t pull_job_header_callback(void *contents, size_t size, size_t nmemb, void *userdata) {
        PullJob *j = userdata;
        size_t sz = size * nmemb;
        _cleanup_free_ char *length = NULL, *last_modified = NULL;
        char *etag;
        int r;

        assert(contents);
        assert(j);

        if (IN_SET(j->state, PULL_JOB_DONE, PULL_JOB_FAILED)) {
                r = -ESTALE;
                goto fail;
        }

        assert(j->state == PULL_JOB_ANALYZING);

        r = curl_header_strdup(contents, sz, "ETag:", &etag);
        if (r < 0) {
                log_oom();
                goto fail;
        }
        if (r > 0) {
                free(j->etag);
                j->etag = etag;

                if (strv_contains(j->old_etags, j->etag)) {
                        log_info("Image already downloaded. Skipping download.");
                        j->etag_exists = true;
                        pull_job_finish(j, 0);
                        return sz;
                }

                return sz;
        }

        r = curl_header_strdup(contents, sz, "Content-Length:", &length);
        if (r < 0) {
                log_oom();
                goto fail;
        }
        if (r > 0) {
                (void) safe_atou64(length, &j->content_length);

                if (j->content_length != (uint64_t) -1) {
                        char bytes[FORMAT_BYTES_MAX];

                        if (j->content_length > j->compressed_max) {
                                log_error("Content too large.");
                                r = -EFBIG;
                                goto fail;
                        }

                        log_info("Downloading %s for %s.", format_bytes(bytes, sizeof(bytes), j->content_length), j->url);
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
        PullJob *j = userdata;
        unsigned percent;
        usec_t n;

        assert(j);

        if (dltotal <= 0)
                return 0;

        percent = ((100 * dlnow) / dltotal);
        n = now(CLOCK_MONOTONIC);

        if (n > j->last_status_usec + USEC_PER_SEC &&
            percent != j->progress_percent &&
            dlnow < dltotal) {
                char buf[FORMAT_TIMESPAN_MAX];

                if (n - j->start_usec > USEC_PER_SEC && dlnow > 0) {
                        char y[FORMAT_BYTES_MAX];
                        usec_t left, done;

                        done = n - j->start_usec;
                        left = (usec_t) (((double) done * (double) dltotal) / dlnow) - done;

                        log_info("Got %u%% of %s. %s left at %s/s.",
                                 percent,
                                 j->url,
                                 format_timespan(buf, sizeof(buf), left, USEC_PER_SEC),
                                 format_bytes(y, sizeof(y), (uint64_t) ((double) dlnow / ((double) done / (double) USEC_PER_SEC))));
                } else
                        log_info("Got %u%% of %s.", percent, j->url);

                j->progress_percent = percent;
                j->last_status_usec = n;

                if (j->on_progress)
                        j->on_progress(j);
        }

        return 0;
}

int pull_job_new(PullJob **ret, const char *url, CurlGlue *glue, void *userdata) {
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
                .disk_fd = -1,
                .userdata = userdata,
                .glue = glue,
                .content_length = (uint64_t) -1,
                .start_usec = now(CLOCK_MONOTONIC),
                .compressed_max = 64LLU * 1024LLU * 1024LLU * 1024LLU, /* 64GB safety limit */
                .uncompressed_max = 64LLU * 1024LLU * 1024LLU * 1024LLU, /* 64GB safety limit */
                .style = VERIFICATION_STYLE_UNSET,
                .url = TAKE_PTR(u),
        };

        *ret = TAKE_PTR(j);

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

                if (!j->request_header) {
                        j->request_header = curl_slist_new(hdr, NULL);
                        if (!j->request_header)
                                return -ENOMEM;
                } else {
                        struct curl_slist *l;

                        l = curl_slist_append(j->request_header, hdr);
                        if (!l)
                                return -ENOMEM;

                        j->request_header = l;
                }
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

        if (curl_easy_setopt(j->curl, CURLOPT_NOPROGRESS, 0) != CURLE_OK)
                return -EIO;

        r = curl_glue_add(j->glue, j->curl);
        if (r < 0)
                return r;

        j->state = PULL_JOB_ANALYZING;

        return 0;
}
