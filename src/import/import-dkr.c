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

#include <curl/curl.h>
#include <sys/prctl.h>

#include "hashmap.h"
#include "set.h"
#include "json.h"
#include "strv.h"
#include "curl-util.h"
#include "import-dkr.h"
#include "btrfs-util.h"
#include "aufs-util.h"
#include "utf8.h"

/* TODO:
  - convert json bits
  - man page
  - fall back to btrfs loop pool device
*/

typedef struct DkrImportJob DkrImportJob;
typedef struct DkrImportName DkrImportName;

typedef enum DkrImportJobType {
        DKR_IMPORT_JOB_IMAGES,
        DKR_IMPORT_JOB_TAGS,
        DKR_IMPORT_JOB_ANCESTRY,
        DKR_IMPORT_JOB_JSON,
        DKR_IMPORT_JOB_LAYER,
} DkrImportJobType;

struct DkrImportJob {
        DkrImport *import;
        DkrImportJobType type;
        bool done;

        char *url;

        Set *needed_by; /* DkrImport Name objects */

        CURL *curl;
        struct curl_slist *request_header;
        void *payload;
        size_t payload_size;

        char *response_token;
        char **response_registries;

        char *temp_path;
        char *final_path;

        pid_t tar_pid;
        FILE *tar_stream;
};

struct DkrImportName {
        DkrImport *import;

        char *index_url;
        char *name;
        char *tag;
        char *id;
        char *local;

        DkrImportJob *job_images, *job_tags, *job_ancestry, *job_json, *job_layer;

        char **ancestry;
        unsigned current_ancestry;

        bool force_local;
};

struct DkrImport {
        sd_event *event;
        CurlGlue *glue;

        Hashmap *names;
        Hashmap *jobs;

        dkr_import_on_finished on_finished;
        void *userdata;
};

#define PROTOCOL_PREFIX "https://"

#define HEADER_TOKEN "X-Do" /* the HTTP header for the auth token */ "cker-Token:"
#define HEADER_REGISTRY "X-Do" /*the HTTP header for the registry */ "cker-Endpoints:"

#define PAYLOAD_MAX (16*1024*1024)
#define LAYERS_MAX 2048

static int dkr_import_name_add_job(DkrImportName *name, DkrImportJobType type, const char *url, DkrImportJob **ret);

static DkrImportJob *dkr_import_job_unref(DkrImportJob *job) {
        if (!job)
                return NULL;

        if (job->import)
                curl_glue_remove_and_free(job->import->glue, job->curl);
        curl_slist_free_all(job->request_header);

        if (job->tar_stream)
                fclose(job->tar_stream);

        free(job->final_path);

        if (job->temp_path) {
                btrfs_subvol_remove(job->temp_path);
                free(job->temp_path);
        }

        set_free(job->needed_by);

        if (job->tar_pid > 0)
                kill(job->tar_pid, SIGTERM);

        free(job->url);
        free(job->payload);
        free(job->response_token);
        strv_free(job->response_registries);

        free(job);

        return NULL;
}

static DkrImportName *dkr_import_name_unref(DkrImportName *name) {
        if (!name)
                return NULL;

        if (name->job_images)
                set_remove(name->job_images->needed_by, name);

        if (name->job_tags)
                set_remove(name->job_tags->needed_by, name);

        if (name->job_ancestry)
                set_remove(name->job_ancestry->needed_by, name);

        if (name->job_json)
                set_remove(name->job_json->needed_by, name);

        if (name->job_layer)
                set_remove(name->job_layer->needed_by, name);

        free(name->index_url);
        free(name->name);
        free(name->id);
        free(name->tag);
        free(name->local);

        strv_free(name->ancestry);
        free(name);

        return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(DkrImportJob*, dkr_import_job_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(DkrImportName*, dkr_import_name_unref);

static void dkr_import_finish(DkrImport *import, int error) {
        assert(import);

        if (import->on_finished)
                import->on_finished(import, error, import->userdata);
        else
                sd_event_exit(import->event, error);
}

static int parse_id(const void *payload, size_t size, char **ret) {
        _cleanup_free_ char *buf = NULL, *id = NULL, *other = NULL;
        union json_value v = {};
        void *json_state = NULL;
        const char *p;
        int t;

        assert(payload);
        assert(ret);

        if (size <= 0)
                return -EBADMSG;

        if (memchr(payload, 0, size))
                return -EBADMSG;

        buf = strndup(payload, size);
        if (!buf)
                return -ENOMEM;

        p = buf;
        t = json_tokenize(&p, &id, &v, &json_state, NULL);
        if (t < 0)
                return t;
        if (t != JSON_STRING)
                return -EBADMSG;

        t = json_tokenize(&p, &other, &v, &json_state, NULL);
        if (t < 0)
                return t;
        if (t != JSON_END)
                return -EBADMSG;

        if (!dkr_id_is_valid(id))
                return -EBADMSG;

        *ret = id;
        id = NULL;

        return 0;
}

static int parse_ancestry(const void *payload, size_t size, char ***ret) {
        _cleanup_free_ char *buf = NULL;
        void *json_state = NULL;
        const char *p;
        enum {
                STATE_BEGIN,
                STATE_ITEM,
                STATE_COMMA,
                STATE_END,
        } state = STATE_BEGIN;
        _cleanup_strv_free_ char **l = NULL;
        size_t n = 0, allocated = 0;

        if (size <= 0)
                return -EBADMSG;

        if (memchr(payload, 0, size))
                return -EBADMSG;

        buf = strndup(payload, size);
        if (!buf)
                return -ENOMEM;

        p = buf;
        for (;;) {
                _cleanup_free_ char *str;
                union json_value v = {};
                int t;

                t = json_tokenize(&p, &str, &v, &json_state, NULL);
                if (t < 0)
                        return t;

                switch (state) {

                case STATE_BEGIN:
                        if (t == JSON_ARRAY_OPEN)
                                state = STATE_ITEM;
                        else
                                return -EBADMSG;

                        break;

                case STATE_ITEM:
                        if (t == JSON_STRING) {
                                if (!dkr_id_is_valid(str))
                                        return -EBADMSG;

                                if (n+1 > LAYERS_MAX)
                                        return -EFBIG;

                                if (!GREEDY_REALLOC(l, allocated, n + 2))
                                        return -ENOMEM;

                                l[n++] = str;
                                str = NULL;
                                l[n] = NULL;

                                state = STATE_COMMA;

                        } else if (t == JSON_ARRAY_CLOSE)
                                state = STATE_END;
                        else
                                return -EBADMSG;

                        break;

                case STATE_COMMA:
                        if (t == JSON_COMMA)
                                state = STATE_ITEM;
                        else if (t == JSON_ARRAY_CLOSE)
                                state = STATE_END;
                        else
                                return -EBADMSG;
                        break;

                case STATE_END:
                        if (t == JSON_END) {

                                if (strv_isempty(l))
                                        return -EBADMSG;

                                if (!strv_is_uniq(l))
                                        return -EBADMSG;

                                l = strv_reverse(l);

                                *ret = l;
                                l = NULL;
                                return 0;
                        } else
                                return -EBADMSG;
                }

        }
}

static const char *dkr_import_name_current_layer(DkrImportName *name) {
        assert(name);

        if (strv_isempty(name->ancestry))
                return NULL;

        return name->ancestry[name->current_ancestry];
}

static const char *dkr_import_name_current_base_layer(DkrImportName *name) {
        assert(name);

        if (strv_isempty(name->ancestry))
                return NULL;

        if (name->current_ancestry <= 0)
                return NULL;

        return name->ancestry[name->current_ancestry-1];
}

static char** dkr_import_name_get_registries(DkrImportName *name) {
        assert(name);

        if (!name->job_images)
                return NULL;

        if (!name->job_images->done)
                return NULL;

        if (strv_isempty(name->job_images->response_registries))
                return NULL;

        return name->job_images->response_registries;
}

static const char*dkr_import_name_get_token(DkrImportName *name) {
        assert(name);

        if (!name->job_images)
                return NULL;

        if (!name->job_images->done)
                return NULL;

        return name->job_images->response_token;
}

static void dkr_import_name_maybe_finish(DkrImportName *name) {
        int r;

        assert(name);

        if (!name->job_images || !name->job_images->done)
                return;

        if (!name->job_ancestry || !name->job_ancestry->done)
                return;

        if (!name->job_json || !name->job_json->done)
                return;

        if (name->job_layer && !name->job_json->done)
                return;

        if (dkr_import_name_current_layer(name))
                return;

        if (name->local) {
                const char *p, *q;

                assert(name->id);

                p = strappenda("/var/lib/container/", name->local);
                q = strappenda("/var/lib/container/.dkr-", name->id);

                if (name->force_local) {
                        (void) btrfs_subvol_remove(p);
                        (void) rm_rf(p, false, true, false);
                }

                r = btrfs_subvol_snapshot(q, p, false, false);
                if (r < 0) {
                        log_error_errno(r, "Failed to snapshot final image: %m");
                        dkr_import_finish(name->import, r);
                        return;
                }

                log_info("Created new image %s.", p);
        }

        dkr_import_finish(name->import, 0);
}

static int dkr_import_job_run_tar(DkrImportJob *job) {
        _cleanup_close_pair_ int pipefd[2] = { -1, -1 };
        bool gzip;

        assert(job);

        /* A stream to run tar on? */
        if (!job->temp_path)
                return 0;

        if (job->tar_stream)
                return 0;

        /* Maybe fork off tar, if we have enough to figure out that
         * something is gzip compressed or not */

        if (job->payload_size < 2)
                return 0;

        /* Detect gzip signature */
        gzip = ((uint8_t*) job->payload)[0] == 0x1f &&
               ((uint8_t*) job->payload)[1] == 0x8b;

        assert(!job->tar_stream);
        assert(job->tar_pid <= 0);

        if (pipe2(pipefd, O_CLOEXEC) < 0)
                return log_error_errno(errno, "Failed to create pipe for tar: %m");

        job->tar_pid = fork();
        if (job->tar_pid < 0)
                return log_error_errno(errno, "Failed to fork off tar: %m");
        if (job->tar_pid == 0) {
                int null_fd;

                reset_all_signal_handlers();
                reset_signal_mask();
                assert_se(prctl(PR_SET_PDEATHSIG, SIGTERM) == 0);

                pipefd[1] = safe_close(pipefd[1]);

                if (dup2(pipefd[0], STDIN_FILENO) != STDIN_FILENO) {
                        log_error_errno(errno, "Failed to dup2() fd: %m");
                        _exit(EXIT_FAILURE);
                }

                if (pipefd[0] != STDIN_FILENO)
                        safe_close(pipefd[0]);
                if (pipefd[1] != STDIN_FILENO)
                        safe_close(pipefd[1]);

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
                        safe_close(null_fd);

                execlp("tar", "tar", "-C", job->temp_path, gzip ? "-xz" : "-x", NULL);
                _exit(EXIT_FAILURE);
        }

        pipefd[0] = safe_close(pipefd[0]);

        job->tar_stream = fdopen(pipefd[1], "w");
        if (!job->tar_stream)
                return log_error_errno(errno, "Failed to allocate tar stream: %m");

        pipefd[1] = -1;

        if (fwrite(job->payload, 1, job->payload_size, job->tar_stream) != job->payload_size)
                return log_error_errno(errno, "Couldn't write payload: %m");

        free(job->payload);
        job->payload = NULL;
        job->payload_size = 0;

        return 0;
}

static int dkr_import_name_pull_layer(DkrImportName *name) {
        _cleanup_free_ char *path = NULL, *temp = NULL;
        const char *url, *layer = NULL, *base = NULL;
        char **rg;
        int r;

        assert(name);

        if (name->job_layer) {
                set_remove(name->job_layer->needed_by, name);
                name->job_layer = NULL;
        }

        for (;;) {
                layer = dkr_import_name_current_layer(name);
                if (!layer) {
                        dkr_import_name_maybe_finish(name);
                        return 0;
                }

                path = strjoin("/var/lib/container/.dkr-", layer, NULL);
                if (!path)
                        return log_oom();

                if (laccess(path, F_OK) < 0) {
                        if (errno == ENOENT)
                                break;

                        return log_error_errno(errno, "Failed to check for container: %m");
                }

                log_info("Layer %s already exists, skipping.", layer);

                name->current_ancestry++;

                free(path);
                path = NULL;
        }

        rg = dkr_import_name_get_registries(name);
        assert(rg && rg[0]);

        url = strappenda(PROTOCOL_PREFIX, rg[0], "/v1/images/", layer, "/layer");
        r = dkr_import_name_add_job(name, DKR_IMPORT_JOB_LAYER, url, &name->job_layer);
        if (r < 0) {
                log_error_errno(r, "Failed to issue HTTP request: %m");
                return r;
        }
        if (r == 0) /* Already downloading this one? */
                return 0;

        log_info("Pulling layer %s...", layer);

        r = tempfn_random(path, &temp);
        if (r < 0)
                return log_oom();

        base = dkr_import_name_current_base_layer(name);
        if (base) {
                const char *base_path;

                base_path = strappend("/var/lib/container/.dkr-", base);
                r = btrfs_subvol_snapshot(base_path, temp, false, true);
        } else
                r = btrfs_subvol_make(temp);

        if (r < 0)
                return log_error_errno(r, "Failed to make btrfs subvolume %s", temp);

        name->job_layer->final_path = path;
        name->job_layer->temp_path = temp;
        path = temp = NULL;

        return 0;
}

static void dkr_import_name_job_finished(DkrImportName *name, DkrImportJob *job) {
        int r;

        assert(name);
        assert(job);

        if (name->job_images == job) {
                const char *url;
                char **rg;

                assert(!name->job_tags);
                assert(!name->job_ancestry);
                assert(!name->job_json);
                assert(!name->job_layer);

                rg = dkr_import_name_get_registries(name);
                if (strv_isempty(rg)) {
                        log_error("Didn't get registry information.");
                        r = -EBADMSG;
                        goto fail;
                }

                log_info("Index lookup succeeded, directed to registry %s.", rg[0]);

                url = strappenda(PROTOCOL_PREFIX, rg[0], "/v1/repositories/", name->name, "/tags/", name->tag);

                r = dkr_import_name_add_job(name, DKR_IMPORT_JOB_TAGS, url, &name->job_tags);
                if (r < 0) {
                        log_error_errno(r, "Failed to issue HTTP request: %m");
                        goto fail;
                }

        } else if (name->job_tags == job) {
                const char *url;
                char *id = NULL, **rg;

                assert(!name->job_ancestry);
                assert(!name->job_json);
                assert(!name->job_layer);

                r = parse_id(job->payload, job->payload_size, &id);
                if (r < 0) {
                        log_error_errno(r, "Failed to parse JSON id.");
                        goto fail;
                }

                free(name->id);
                name->id = id;

                rg = dkr_import_name_get_registries(name);
                assert(rg && rg[0]);

                log_info("Tag lookup succeeded, resolved to layer %s.", name->id);

                url = strappenda(PROTOCOL_PREFIX, rg[0], "/v1/images/", name->id, "/ancestry");
                r = dkr_import_name_add_job(name, DKR_IMPORT_JOB_ANCESTRY, url, &name->job_ancestry);
                if (r < 0) {
                        log_error_errno(r, "Failed to issue HTTP request: %m");
                        goto fail;
                }

                url = strappenda(PROTOCOL_PREFIX, rg[0], "/v1/images/", name->id, "/json");
                r = dkr_import_name_add_job(name, DKR_IMPORT_JOB_JSON, url, &name->job_json);
                if (r < 0) {
                        log_error_errno(r, "Failed to issue HTTP request: %m");
                        goto fail;
                }

        } else if (name->job_ancestry == job) {
                char **ancestry = NULL, **i;
                unsigned n;

                r = parse_ancestry(job->payload, job->payload_size, &ancestry);
                if (r < 0) {
                        log_error_errno(r, "Failed to parse JSON id.");
                        goto fail;
                }

                n = strv_length(ancestry);
                if (n <= 0 || !streq(ancestry[n-1], name->id)) {
                        log_error("Ancestry doesn't end in main layer.");
                        r = -EBADMSG;
                        goto fail;
                }

                log_info("Ancestor lookup succeeded, requires layers:\n");
                STRV_FOREACH(i, ancestry)
                        log_info("\t%s", *i);

                strv_free(name->ancestry);
                name->ancestry = ancestry;

                name->current_ancestry = 0;
                r = dkr_import_name_pull_layer(name);
                if (r < 0)
                        goto fail;

        } else if (name->job_json == job) {

                dkr_import_name_maybe_finish(name);

        } else if (name->job_layer == job) {

                name->current_ancestry ++;
                r = dkr_import_name_pull_layer(name);
                if (r < 0)
                        goto fail;

        } else
                assert_not_reached("Got finished event for unknown curl object");

        return;

fail:
        dkr_import_finish(name->import, r);
}

static void dkr_import_curl_on_finished(CurlGlue *g, CURL *curl, CURLcode result) {
        DkrImportJob *job = NULL;
        CURLcode code;
        DkrImportName *n;
        long status;
        Iterator i;
        int r;

        if (curl_easy_getinfo(curl, CURLINFO_PRIVATE, &job) != CURLE_OK)
                return;

        if (!job)
                return;

        job->done = true;

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
        } else if (status >= 300) {
                log_error("HTTP request to %s failed with code %li.", job->url, status);
                r = -EIO;
                goto fail;
        } else if (status < 200) {
                log_error("HTTP request to %s finished with unexpected code %li.", job->url, status);
                r = -EIO;
                goto fail;
        }

        switch (job->type) {

        case DKR_IMPORT_JOB_LAYER: {
                siginfo_t si;

                if (!job->tar_stream) {
                        log_error("Downloaded layer too short.");
                        r = -EIO;
                        goto fail;
                }

                fclose(job->tar_stream);
                job->tar_stream = NULL;

                assert(job->tar_pid > 0);

                r = wait_for_terminate(job->tar_pid, &si);
                if (r < 0) {
                        log_error_errno(r, "Failed to wait for tar process: %m");
                        goto fail;
                }

                job->tar_pid = 0;

                if (si.si_code != CLD_EXITED || si.si_status != EXIT_SUCCESS) {
                        log_error_errno(r, "tar failed abnormally.");
                        r = -EIO;
                        goto fail;
                }

                r = aufs_resolve(job->temp_path);
                if (r < 0) {
                        log_error_errno(r, "Couldn't resolve aufs whiteouts: %m");
                        goto fail;
                }

                r = btrfs_subvol_read_only(job->temp_path, true);
                if (r < 0) {
                        log_error_errno(r, "Failed to mark snapshot read-only: %m");
                        goto fail;
                }

                if (rename(job->temp_path, job->final_path) < 0) {
                        log_error_errno(r, "Failed to rename snapshot: %m");
                        goto fail;
                }

                log_info("Completed writing to layer %s", job->final_path);
                break;
        }

        default:
                ;
        }

        SET_FOREACH(n, job->needed_by, i)
                dkr_import_name_job_finished(n, job);

        return;

fail:
        dkr_import_finish(job->import, r);
}

static size_t dkr_import_job_write_callback(void *contents, size_t size, size_t nmemb, void *userdata) {
        DkrImportJob *j = userdata;
        size_t sz = size * nmemb;
        char *p;
        int r;

        assert(contents);
        assert(j);

        if (j->tar_stream) {
                size_t l;

                l = fwrite(contents, size, nmemb, j->tar_stream);
                if (l != nmemb) {
                        r = -errno;
                        goto fail;
                }

                return l;
        }

        if (j->payload_size + sz > PAYLOAD_MAX) {
                r = -EFBIG;
                goto fail;
        }

        p = realloc(j->payload, j->payload_size + sz);
        if (!p) {
                r = -ENOMEM;
                goto fail;
        }

        memcpy(p + j->payload_size, contents, sz);
        j->payload_size += sz;
        j->payload = p;

        r = dkr_import_job_run_tar(j);
        if (r < 0)
                goto fail;

        return sz;

fail:
        dkr_import_finish(j->import, r);
        return 0;
}

static size_t dkr_import_job_header_callback(void *contents, size_t size, size_t nmemb, void *userdata) {
        _cleanup_free_ char *registry = NULL;
        size_t sz = size * nmemb;
        DkrImportJob *j = userdata;
        char *token;
        int r;

        assert(contents);
        assert(j);

        r = curl_header_strdup(contents, sz, HEADER_TOKEN, &token);
        if (r < 0) {
                log_oom();
                goto fail;
        }
        if (r > 0) {
                free(j->response_token);
                j->response_token = token;
        }

        r = curl_header_strdup(contents, sz, HEADER_REGISTRY, &registry);
        if (r < 0) {
                log_oom();
                goto fail;
        }
        if (r > 0) {
                char **l, **i;

                l = strv_split(registry, ",");
                if (!l) {
                        r = log_oom();
                        goto fail;
                }

                STRV_FOREACH(i, l) {
                        if (!hostname_is_valid(*i)) {
                                log_error("Registry hostname is not valid.");
                                strv_free(l);
                                r = -EBADMSG;
                                goto fail;
                        }
                }

                strv_free(j->response_registries);
                j->response_registries = l;
        }

        return sz;

fail:
        dkr_import_finish(j->import, r);
        return 0;
}

static int dkr_import_name_add_job(DkrImportName *name, DkrImportJobType type, const char *url, DkrImportJob **ret) {
        _cleanup_(dkr_import_job_unrefp) DkrImportJob *j = NULL;
        DkrImportJob *f = NULL;
        const char *t, *token;
        int r;

        assert(name);
        assert(url);
        assert(ret);

        log_info("Getting %s.", url);
        f = hashmap_get(name->import->jobs, url);
        if (f) {
                if (f->type != type)
                        return -EINVAL;

                r = set_put(f->needed_by, name);
                if (r < 0)
                        return r;

                return 0;
        }

        r = hashmap_ensure_allocated(&name->import->jobs, &string_hash_ops);
        if (r < 0)
                return r;

        j = new0(DkrImportJob, 1);
        if (!j)
                return -ENOMEM;

        j->import = name->import;
        j->type = type;
        j->url = strdup(url);
        if (!j->url)
                return -ENOMEM;

        r = set_ensure_allocated(&j->needed_by, &trivial_hash_ops);
        if (r < 0)
                return r;

        r = curl_glue_make(&j->curl, j->url, j);
        if (r < 0)
                return r;

        token = dkr_import_name_get_token(name);
        if (token)
                t = strappenda("Authorization: Token ", token);
        else
                t = HEADER_TOKEN " true";

        j->request_header = curl_slist_new("Accept: application/json", t, NULL);
        if (!j->request_header)
                return -ENOMEM;

        if (curl_easy_setopt(j->curl, CURLOPT_HTTPHEADER, j->request_header) != CURLE_OK)
                return -EIO;

        if (curl_easy_setopt(j->curl, CURLOPT_WRITEFUNCTION, dkr_import_job_write_callback) != CURLE_OK)
                return -EIO;

        if (curl_easy_setopt(j->curl, CURLOPT_WRITEDATA, j) != CURLE_OK)
                return -EIO;

        if (curl_easy_setopt(j->curl, CURLOPT_HEADERFUNCTION, dkr_import_job_header_callback) != CURLE_OK)
                return -EIO;

        if (curl_easy_setopt(j->curl, CURLOPT_HEADERDATA, j) != CURLE_OK)
                return -EIO;

        r = curl_glue_add(name->import->glue, j->curl);
        if (r < 0)
                return r;

        r = hashmap_put(name->import->jobs, j->url, j);
        if (r < 0)
                return r;

        r = set_put(j->needed_by, name);
        if (r < 0) {
                hashmap_remove(name->import->jobs, url);
                return r;
        }

        *ret = j;
        j = NULL;

        return 1;
}

static int dkr_import_name_begin(DkrImportName *name) {
        const char *url;

        assert(name);
        assert(!name->job_images);

        url = strappenda(name->index_url, "/v1/repositories/", name->name, "/images");

        return dkr_import_name_add_job(name, DKR_IMPORT_JOB_IMAGES, url, &name->job_images);
}

int dkr_import_new(DkrImport **import, sd_event *event, dkr_import_on_finished on_finished, void *userdata) {
        _cleanup_(dkr_import_unrefp) DkrImport *i = NULL;
        int r;

        assert(import);

        i = new0(DkrImport, 1);
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

        i->glue->on_finished = dkr_import_curl_on_finished;
        i->glue->userdata = i;

        *import = i;
        i = NULL;

        return 0;
}

DkrImport* dkr_import_unref(DkrImport *import) {
        DkrImportName *n;
        DkrImportJob *j;

        if (!import)
                return NULL;

        while ((n = hashmap_steal_first(import->names)))
               dkr_import_name_unref(n);
        hashmap_free(import->names);

        while ((j = hashmap_steal_first(import->jobs)))
                dkr_import_job_unref(j);
        hashmap_free(import->jobs);

        curl_glue_unref(import->glue);
        sd_event_unref(import->event);

        free(import);

        return NULL;
}

int dkr_import_cancel(DkrImport *import, const char *name) {
        DkrImportName *n;

        assert(import);
        assert(name);

        n = hashmap_remove(import->names, name);
        if (!n)
                return 0;

        dkr_import_name_unref(n);
        return 1;
}

int dkr_import_pull(DkrImport *import, const char *index_url, const char *name, const char *tag, const char *local, bool force_local) {
        _cleanup_(dkr_import_name_unrefp) DkrImportName *n = NULL;
        char *e;
        int r;

        assert(import);
        assert(dkr_url_is_valid(index_url));
        assert(dkr_name_is_valid(name));
        assert(dkr_tag_is_valid(tag));
        assert(!local || machine_name_is_valid(local));

        if (hashmap_get(import->names, name))
                return -EEXIST;

        r = hashmap_ensure_allocated(&import->names, &string_hash_ops);
        if (r < 0)
                return r;

        n = new0(DkrImportName, 1);
        if (!n)
                return -ENOMEM;

        n->import = import;

        n->index_url = strdup(index_url);
        if (!n->index_url)
                return -ENOMEM;
        e = endswith(n->index_url, "/");
        if (e)
                *e = 0;

        n->name = strdup(name);
        if (!n->name)
                return -ENOMEM;

        n->tag = strdup(tag);
        if (!n->tag)
                return -ENOMEM;

        if (local) {
                n->local = strdup(local);
                if (!n->local)
                        return -ENOMEM;
                n->force_local = force_local;
        }

        r = hashmap_put(import->names, name, n);
        if (r < 0)
                return r;

        r = dkr_import_name_begin(n);
        if (r < 0) {
                dkr_import_cancel(import, n->name);
                n = NULL;
                return r;
        }

        n = NULL;

        return 0;
}

bool dkr_name_is_valid(const char *name) {
        const char *slash, *p;

        if (isempty(name))
                return false;

        slash = strchr(name, '/');
        if (!slash)
                return false;

        if (!filename_is_valid(slash + 1))
                return false;

        p = strndupa(name, slash - name);
        if (!filename_is_valid(p))
                return false;

        return true;
}

bool dkr_id_is_valid(const char *id) {

        if (!filename_is_valid(id))
                return false;

        if (!in_charset(id, "0123456789abcdef"))
                return false;

        return true;
}

bool dkr_url_is_valid(const char *url) {

        if (!startswith(url, "http://") &&
            !startswith(url, "https://"))
                return false;

        return ascii_is_valid(url);
}
