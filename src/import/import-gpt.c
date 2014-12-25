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
#include <curl/curl.h>

#include "hashmap.h"
#include "utf8.h"
#include "curl-util.h"
#include "import-gpt.h"

typedef struct GptImportFile GptImportFile;

struct GptImportFile {
        GptImport *import;

        char *url;
        char *local;

        CURL *curl;
        struct curl_slist *request_header;

        char *temp_path;
        char *final_path;
        char *etag;
        char *old_etag;

        uint64_t content_length;
        uint64_t written;

        usec_t mtime;

        bool force_local;
        bool done;

        int disk_fd;
};

struct GptImport {
        sd_event *event;
        CurlGlue *glue;

        Hashmap *files;

        gpt_import_on_finished on_finished;
        void *userdata;

        bool finished;
};

static GptImportFile *gpt_import_file_unref(GptImportFile *f) {
        if (!f)
                return NULL;

        if (f->import)
                curl_glue_remove_and_free(f->import->glue, f->curl);
        curl_slist_free_all(f->request_header);

        safe_close(f->disk_fd);

        free(f->final_path);

        if (f->temp_path) {
                unlink(f->temp_path);
                free(f->temp_path);
        }

        free(f->url);
        free(f->local);
        free(f->etag);
        free(f->old_etag);
        free(f);

        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(GptImportFile*, gpt_import_file_unref);

static void gpt_import_finish(GptImport *import, int error) {
        assert(import);

        if (import->finished)
                return;

        import->finished = true;

        if (import->on_finished)
                import->on_finished(import, error, import->userdata);
        else
                sd_event_exit(import->event, error);
}

static void gpt_import_curl_on_finished(CurlGlue *g, CURL *curl, CURLcode result) {
        GptImportFile *f = NULL;
        struct stat st;
        CURLcode code;
        long status;
        int r;

        if (curl_easy_getinfo(curl, CURLINFO_PRIVATE, &f) != CURLE_OK)
                return;

        if (!f)
                return;

        f->done = true;

        if (result != CURLE_OK) {
                log_error("Transfer failed: %s", curl_easy_strerror(result));
                r = -EIO;
                goto fail;
        }

        code = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
        if (code != CURLE_OK) {
                log_error("Failed to retrieve response code: %s", curl_easy_strerror(code));
                r = -EIO;
                goto fail;
        } else if (status == 304) {
                log_info("File unmodified.");
                r = 0;
                goto fail;
        } else if (status >= 300) {
                log_error("HTTP request to %s failed with code %li.", f->url, status);
                r = -EIO;
                goto fail;
        } else if (status < 200) {
                log_error("HTTP request to %s finished with unexpected code %li.", f->url, status);
                r = -EIO;
                goto fail;
        }

        if (f->disk_fd < 0) {
                log_error("No data received.");
                r = -EIO;
                goto fail;
        }

        if (f->content_length != (uint64_t) -1 &&
            f->content_length != f->written) {
                log_error("Download truncated.");
                r = -EIO;
                goto fail;
        }

        if (f->etag)
                (void) fsetxattr(f->disk_fd, "user.etag", f->etag, strlen(f->etag), XATTR_CREATE);

        if (f->mtime != 0) {
                struct timespec ut[2];

                timespec_store(&ut[0], f->mtime);
                ut[1] = ut[0];

                (void) futimens(f->disk_fd, ut);
        }

        if (fstat(f->disk_fd, &st) < 0) {
                r = log_error_errno(errno, "Failed to stat file: %m");
                goto fail;
        }

        /* Mark read-only */
        (void) fchmod(f->disk_fd, st.st_mode & 07444);

        f->disk_fd = safe_close(f->disk_fd);

        assert(f->temp_path);
        assert(f->final_path);

        r = rename(f->temp_path, f->final_path);
        if (r < 0) {
                r = log_error_errno(errno, "Failed to move GPT file into place: %m");
                goto fail;
        }

        r = 0;

fail:
        gpt_import_finish(f->import, r);
}

static int gpt_import_file_open_disk(GptImportFile *f) {
        int r;

        assert(f);

        if (f->disk_fd >= 0)
                return 0;

        assert(f->final_path);

        if (!f->temp_path) {
                r = tempfn_random(f->final_path, &f->temp_path);
                if (r < 0)
                        return log_oom();
        }

        f->disk_fd = open(f->temp_path, O_CREAT|O_EXCL|O_NOCTTY|O_CLOEXEC|O_WRONLY, 0644);
        if (f->disk_fd < 0)
                return log_error_errno(errno, "Failed to create %s: %m", f->temp_path);

        return 0;
}

static size_t gpt_import_file_write_callback(void *contents, size_t size, size_t nmemb, void *userdata) {
        GptImportFile *f = userdata;
        size_t sz = size * nmemb;
        ssize_t n;
        int r;

        assert(contents);
        assert(f);

        r = gpt_import_file_open_disk(f);
        if (r < 0)
                goto fail;

        if (f->written + sz < f->written) {
                log_error("File too large, overflow");
                r = -EOVERFLOW;
                goto fail;
        }

        if (f->content_length != (uint64_t) -1 &&
            f->written + sz > f->content_length) {
                log_error("Content length incorrect.");
                r = -EFBIG;
                goto fail;
        }

        n = write(f->disk_fd, contents, sz);
        if (n < 0) {
                log_error_errno(errno, "Failed to write file: %m");
                goto fail;
        }

        if ((size_t) n < sz) {
                log_error("Short write");
                r = -EIO;
                goto fail;
        }

        f->written += sz;

        return sz;

fail:
        gpt_import_finish(f->import, r);
        return 0;
}

static size_t gpt_import_file_header_callback(void *contents, size_t size, size_t nmemb, void *userdata) {
        GptImportFile *f = userdata;
        size_t sz = size * nmemb;
        _cleanup_free_ char *length = NULL, *last_modified = NULL;
        char *etag;
        int r;

        assert(contents);
        assert(f);

        r = curl_header_strdup(contents, sz, "ETag:", &etag);
        if (r < 0) {
                log_oom();
                goto fail;
        }
        if (r > 0) {
                free(f->etag);
                f->etag = etag;

                if (streq_ptr(f->old_etag, f->etag)) {
                        log_info("Image already up to date. Finishing.");
                        gpt_import_finish(f->import, 0);
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
                (void) safe_atou64(length, &f->content_length);
                return sz;
        }

        r = curl_header_strdup(contents, sz, "Last-Modified:", &last_modified);
        if (r < 0) {
                log_oom();
                goto fail;
        }
        if (r > 0) {
                (void) curl_parse_http_time(last_modified, &f->mtime);
                return sz;
        }

        return sz;

fail:
        gpt_import_finish(f->import, r);
        return 0;
}

static int gpt_import_file_begin(GptImportFile *f) {
        int r;

        assert(f);
        assert(!f->curl);

        log_info("Getting %s.", f->url);

        r = curl_glue_make(&f->curl, f->url, f);
        if (r < 0)
                return r;

        if (f->old_etag) {
                const char *hdr;

                hdr = strappenda("If-None-Match: ", f->old_etag);

                f->request_header = curl_slist_new(hdr, NULL);
                if (!f->request_header)
                        return -ENOMEM;

                if (curl_easy_setopt(f->curl, CURLOPT_HTTPHEADER, f->request_header) != CURLE_OK)
                        return -EIO;
        }

        if (curl_easy_setopt(f->curl, CURLOPT_WRITEFUNCTION, gpt_import_file_write_callback) != CURLE_OK)
                return -EIO;

        if (curl_easy_setopt(f->curl, CURLOPT_WRITEDATA, f) != CURLE_OK)
                return -EIO;

        if (curl_easy_setopt(f->curl, CURLOPT_HEADERFUNCTION, gpt_import_file_header_callback) != CURLE_OK)
                return -EIO;

        if (curl_easy_setopt(f->curl, CURLOPT_HEADERDATA, f) != CURLE_OK)
                return -EIO;

        r = curl_glue_add(f->import->glue, f->curl);
        if (r < 0)
                return r;

        return 0;
}

int gpt_import_new(GptImport **import, sd_event *event, gpt_import_on_finished on_finished, void *userdata) {
        _cleanup_(gpt_import_unrefp) GptImport *i = NULL;
        int r;

        assert(import);

        i = new0(GptImport, 1);
        if (!i)
                return -ENOMEM;

        i->on_finished = on_finished;
        i->userdata = userdata;

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

        i->glue->on_finished = gpt_import_curl_on_finished;
        i->glue->userdata = i;

        *import = i;
        i = NULL;

        return 0;
}

GptImport* gpt_import_unref(GptImport *import) {
        GptImportFile *f;

        if (!import)
                return NULL;

        while ((f = hashmap_steal_first(import->files)))
                gpt_import_file_unref(f);
        hashmap_free(import->files);

        curl_glue_unref(import->glue);
        sd_event_unref(import->event);

        free(import);

        return NULL;
}

int gpt_import_cancel(GptImport *import, const char *url) {
        GptImportFile *f;

        assert(import);
        assert(url);

        f = hashmap_remove(import->files, url);
        if (!f)
                return 0;

        gpt_import_file_unref(f);
        return 1;
}

int gpt_import_pull(GptImport *import, const char *url, const char *local, bool force_local) {
        _cleanup_(gpt_import_file_unrefp) GptImportFile *f = NULL;
        char etag[LINE_MAX];
        ssize_t n;
        int r;

        assert(import);
        assert(gpt_url_is_valid(url));
        assert(machine_name_is_valid(local));

        if (hashmap_get(import->files, url))
                return -EEXIST;

        r = hashmap_ensure_allocated(&import->files, &string_hash_ops);
        if (r < 0)
                return r;

        f = new0(GptImportFile, 1);
        if (!f)
                return -ENOMEM;

        f->import = import;
        f->disk_fd = -1;
        f->content_length = (uint64_t) -1;

        f->url = strdup(url);
        if (!f->url)
                return -ENOMEM;

        f->local = strdup(local);
        if (!f->local)
                return -ENOMEM;

        f->final_path = strjoin("/var/lib/container/", local, ".gpt", NULL);
        if (!f->final_path)
                return -ENOMEM;

        n = getxattr(f->final_path, "user.etag", etag, sizeof(etag));
        if (n > 0) {
                f->old_etag = strndup(etag, n);
                if (!f->old_etag)
                        return -ENOMEM;
        }

        r = hashmap_put(import->files, f->url, f);
        if (r < 0)
                return r;

        r = gpt_import_file_begin(f);
        if (r < 0) {
                gpt_import_cancel(import, f->url);
                f = NULL;
                return r;
        }

        f = NULL;
        return 0;
}

bool gpt_url_is_valid(const char *url) {
        if (isempty(url))
                return false;

        if (!startswith(url, "http://") &&
            !startswith(url, "https://"))
                return false;

        return ascii_is_valid(url);
}
