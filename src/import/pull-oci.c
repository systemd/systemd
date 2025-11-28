/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"
#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "architecture.h"
#include "btrfs-util.h"
#include "cleanup-util.h"
#include "curl-util.h"
#include "dissect-image.h"
#include "errno-util.h"
#include "escape.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fs-util.h"
#include "hexdecoct.h"
#include "install-file.h"
#include "io-util.h"
#include "json-util.h"
#include "mkdir-label.h"
#include "oci-util.h"
#include "ordered-set.h"
#include "path-util.h"
#include "pidref.h"
#include "process-util.h"
#include "pull-common.h"
#include "pull-oci.h"
#include "rm-rf.h"
#include "set.h"
#include "signal-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "tmpfile-util.h"

#define LAYER_MAX 4096U
#define ACTIVE_LAYERS_MAX 5U

typedef enum OciProgress {
        OCI_DOWNLOADING_MANIFEST,
        OCI_DOWNLOADING_LAYERS,
        OCI_FINALIZING,
        OCI_COPYING,
} OciProgress;

typedef struct OciPull {
        sd_event *event;
        CurlGlue *glue;

        ImportFlags flags;
        char *image_root;

        char *protocol;
        char *repository;
        char *image;
        char *tag;

        PullJob *manifest_job;
        PullJob *bearer_token_job;
        PullJob *config_job;
        OrderedSet *queued_layer_jobs;
        Set *active_layer_jobs, *done_layer_jobs;

        OciPullFinished on_finished;
        void *userdata;

        bool refuse_index; /* if true, refuse processing an OCI index, because we already processed one */

        char *bearer_token;

        char *local;

        struct iovec *layer_digests;
        size_t n_layers;

        struct iovec config;
        int userns_fd;
} OciPull;

typedef struct OciLayerState {
        OciPull *pull;

        PidRef tar_pid;
        char *temp_path;
        char *final_path;

        int tree_fd;
} OciLayerState;

static void oci_pull_job_on_finished_layer(PullJob *j);
static void oci_pull_job_on_finished_manifest(PullJob *j);
static void oci_pull_job_on_finished_config(PullJob *j);
static int oci_pull_work(OciPull *i);

static OciLayerState* oci_layer_state_free(OciLayerState *st) {
        if (!st)
                return NULL;

        pidref_done_sigkill_wait(&st->tar_pid);

        if (st->temp_path) {
                import_remove_tree(st->temp_path, st->pull ? &st->pull->userns_fd : NULL, st->pull->flags);
                free(st->temp_path);
        }
        free(st->final_path);

        safe_close(st->tree_fd);

        return mfree(st);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(OciLayerState*, oci_layer_state_free);

OciPull* oci_pull_unref(OciPull *i) {
        if (!i)
                return NULL;

        pull_job_unref(i->manifest_job);
        pull_job_unref(i->bearer_token_job);
        pull_job_unref(i->config_job);
        ordered_set_free(i->queued_layer_jobs);
        set_free(i->active_layer_jobs);
        set_free(i->done_layer_jobs);

        curl_glue_unref(i->glue);
        sd_event_unref(i->event);

        free(i->protocol);
        free(i->repository);
        free(i->image);
        free(i->tag);

        free(i->image_root);
        free(i->local);
        free(i->bearer_token);

        iovec_done(&i->config);

        iovec_done_many_and_free(i->layer_digests, i->n_layers);

        safe_close(i->userns_fd);

        return mfree(i);
}

int oci_pull_new(
                OciPull **ret,
                sd_event *event,
                const char *image_root,
                OciPullFinished on_finished,
                void *userdata) {

        int r;

        assert(image_root);
        assert(ret);

        _cleanup_free_ char *root = strdup(image_root);
        if (!root)
                return -ENOMEM;

        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        if (event)
                e = sd_event_ref(event);
        else {
                r = sd_event_default(&e);
                if (r < 0)
                        return r;
        }

        _cleanup_(curl_glue_unrefp) CurlGlue *g = NULL;
        r = curl_glue_new(&g, e);
        if (r < 0)
                return r;

        _cleanup_(oci_pull_unrefp) OciPull *i = NULL;
        i = new(OciPull, 1);
        if (!i)
                return -ENOMEM;

        *i = (OciPull) {
                .on_finished = on_finished,
                .userdata = userdata,
                .image_root = TAKE_PTR(root),
                .event = TAKE_PTR(e),
                .glue = TAKE_PTR(g),
                .userns_fd = -EBADF,
        };

        i->glue->on_finished = pull_job_curl_on_finished;
        i->glue->userdata = i;

        *ret = TAKE_PTR(i);

        return 0;
}

static int pull_job_payload_as_json(PullJob *j, sd_json_variant **ret) {
        int r;

        assert(j);
        assert(ret);

        /* The PullJob logic implicitly NUL terminates */
        assert(((char*) j->payload.iov_base)[j->payload.iov_len] == 0);

        if (memchr(j->payload.iov_base, 0, j->payload.iov_len))
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Embedded NUL byte in JSON data, refusing.");

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        unsigned line = 0, column = 0;
        r = sd_json_parse((char*) j->payload.iov_base, /* flags= */ 0, &v, &line, &column);
        if (r < 0)
                return log_error_errno(r, "Failed to parse JSON at position %u:%u: %m", line, column);

        if (DEBUG_LOGGING)
                sd_json_variant_dump(v, SD_JSON_FORMAT_COLOR_AUTO|SD_JSON_FORMAT_PRETTY_AUTO, /* f= */ NULL, /* prefix= */ NULL);

        *ret = TAKE_PTR(v);
        return 0;
}

typedef struct OciIndexEntry {
        char *media_type;
        struct iovec digest;
        uint64_t size;
        char **url;
        char *os;
        char *architecture;
        char *variant;
} OciIndexEntry;

static void oci_index_entry_done(OciIndexEntry *entry) {
        assert(entry);

        entry->media_type = mfree(entry->media_type);
        iovec_done(&entry->digest);
        entry->url = strv_free(entry->url);
        entry->os = mfree(entry->os);
        entry->architecture = mfree(entry->architecture);
        entry->variant = mfree(entry->variant);
}

static bool oci_index_entry_match(OciIndexEntry *entry) {
        assert(entry);

        if (entry->os && !streq(entry->os, "linux"))
                return false;

        if (entry->architecture && go_arch_from_string(entry->architecture) != native_architecture())
                return false;

        return true;
}

static int json_dispatch_oci_digest(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        struct iovec *field = ASSERT_PTR(userdata);
        int r;

        assert(variant);

        const char *s = NULL;
        r = sd_json_dispatch_const_string(name, variant, flags, &s);
        if (r < 0)
                return r;

        const char *h = startswith(s, "sha256:");
        if (!h)
                return json_log(variant, flags, SYNTHETIC_ERRNO(EOPNOTSUPP), "Unsupported hash algorithm used in '%s', refusing.", s);

        _cleanup_(iovec_done) struct iovec d = {};
        r = unhexmem(h, &d.iov_base, &d.iov_len);
        if (r < 0)
                return json_log(variant, flags, r, "Failed to decode hash '%s', refusing.", s);
        if (d.iov_len != SHA256_DIGEST_SIZE)
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "Hash '%s' has wrong size, refusing.", s);

        iovec_done(field);
        *field = TAKE_STRUCT(d);

        return 0;
}

static int json_dispatch_oci_platform(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        OciIndexEntry *entry = ASSERT_PTR(userdata);

        assert(variant);

        static const struct sd_json_dispatch_field table[] = {
                { "os",           SD_JSON_VARIANT_STRING, sd_json_dispatch_string, offsetof(OciIndexEntry, os),           0 },
                { "architecture", SD_JSON_VARIANT_STRING, sd_json_dispatch_string, offsetof(OciIndexEntry, architecture), 0 },
                { "variant",      SD_JSON_VARIANT_STRING, sd_json_dispatch_string, offsetof(OciIndexEntry, variant),      0 },
                {}
        };

        return sd_json_dispatch(variant, table, flags|SD_JSON_ALLOW_EXTENSIONS, entry);
}

static int json_dispatch_oci_index_entry(sd_json_variant *v, OciIndexEntry *entry) {
        int r;

        assert(v);
        assert(entry);

        static const struct sd_json_dispatch_field dispatch_table[] = {
                { "mediaType", SD_JSON_VARIANT_STRING,   sd_json_dispatch_string,      offsetof(OciIndexEntry, media_type), SD_JSON_MANDATORY },
                { "digest",    SD_JSON_VARIANT_STRING,   json_dispatch_oci_digest,     offsetof(OciIndexEntry, digest),     SD_JSON_MANDATORY },
                { "size",      SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uint64,      offsetof(OciIndexEntry, size),       SD_JSON_MANDATORY },
                { "urls",      SD_JSON_VARIANT_ARRAY,    sd_json_dispatch_strv,        offsetof(OciIndexEntry, url),        0                 },
                { "platform",  SD_JSON_VARIANT_OBJECT,   json_dispatch_oci_platform,   0,                                           0                 },
                {}
        };

        r = sd_json_dispatch(v, dispatch_table, SD_JSON_ALLOW_EXTENSIONS|SD_JSON_LOG, entry);
        if (r < 0)
                return r;

        if (!streq_ptr(entry->media_type, "application/vnd.oci.image.manifest.v1+json")) {
                json_log(v, SD_JSON_LOG, /* error= */ 0, "Unexpected manifest index entry with media type '%s', skipping.", entry->media_type);
                return 0;
        }

        return 1;
}

static int oci_pull_redirect_manifest(OciPull *i, const OciIndexEntry *entry) {
        int r;

        assert(i);
        assert(entry);

        /* We acquired an index already and found the right manifest to select, hence let's acquire that one
         * now */

        _cleanup_free_ char *p = oci_digest_string(&entry->digest);
        if (!p)
                return -ENOMEM;

        _cleanup_free_ char *url = NULL;
        r = oci_make_manifest_url(i->protocol, i->repository, i->image, p, &url);
        if (r < 0)
                return r;

        _cleanup_(pull_job_unrefp) PullJob *j = NULL;
        r = pull_job_new(&j, url, i->glue, i);
        if (r < 0)
                return r;

        r = pull_job_set_accept(
                        j,
                        STRV_MAKE("application/vnd.oci.image.manifest.v1+json"));
        if (r < 0)
                return r;

        if (i->bearer_token) {
                r = pull_job_set_bearer_token(j, i->bearer_token);
                if (r < 0)
                        return r;
        }

        j->on_finished = oci_pull_job_on_finished_manifest;
        j->calc_checksum = true;
        if (!iovec_memdup(&entry->digest, &j->checksum))
                return -ENOMEM;

        j->description = strjoin("Image Manifest (", url, ")");
        if (!j->description)
                return -ENOMEM;

        r = pull_job_begin(j);
        if (r < 0)
                return r;

        free_and_replace_full(i->manifest_job, j, pull_job_unref);
        return 0;
}

static int oci_pull_process_index(OciPull *i, PullJob *j) {
        int r;

        assert(i);
        assert(j);

        /* Processes a just downloaded OCI image index, as per:
         *
         * https://github.com/opencontainers/image-spec/blob/main/image-index.md */

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        r = pull_job_payload_as_json(j, &v);
        if (r < 0)
                return r;

        struct {
                unsigned schema_version;
                const char *media_type;
                sd_json_variant *manifests;
        } index_data = {
                .schema_version = UINT_MAX,
        };

        static const struct sd_json_dispatch_field dispatch_table[] = {
                { "schemaVersion", SD_JSON_VARIANT_INTEGER, sd_json_dispatch_uint,          voffsetof(index_data, schema_version), SD_JSON_MANDATORY },
                { "mediaType",     SD_JSON_VARIANT_STRING,  sd_json_dispatch_const_string,  voffsetof(index_data, media_type),     0                 },
                { "manifests",     SD_JSON_VARIANT_ARRAY,   sd_json_dispatch_variant_noref, voffsetof(index_data, manifests),      SD_JSON_MANDATORY },
                {}
        };

        r = sd_json_dispatch(v, dispatch_table, SD_JSON_ALLOW_EXTENSIONS|SD_JSON_LOG, &index_data);
        if (r < 0)
                return r;

        if (index_data.schema_version != 2)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "OCI image index has unsupported schema version %u, refusing.", index_data.schema_version);
        if (index_data.media_type && !streq(index_data.media_type, "application/vnd.oci.image.index.v1+json"))
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "OCI image index has unexpected media type '%s', refusing.", index_data.media_type);

        sd_json_variant *m;
        JSON_VARIANT_ARRAY_FOREACH(m, index_data.manifests) {
                _cleanup_(oci_index_entry_done) OciIndexEntry entry = {
                        .size = UINT64_MAX,
                };

                r = json_dispatch_oci_index_entry(m, &entry);
                if (r < 0)
                        return r;
                if (r == 0) /* skip? */
                        continue;

                if (!oci_index_entry_match(&entry))
                        continue;

                r = oci_pull_redirect_manifest(i, &entry);
                if (r < 0)
                        return r;

                return 1; /* continue */
        }

        return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "No suitable OCI image manifest found for local system.");
}

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(pull_job_hash_ops, void, trivial_hash_func, trivial_compare_func, PullJob, pull_job_unref);

static int oci_pull_job_on_open_disk(PullJob *j) {
        int r;

        assert(j);

        OciLayerState *st = ASSERT_PTR(j->userdata);
        OciPull *i = st->pull;

        if (!st->temp_path) {
                r = tempfn_random_child(i->image_root, "oci", &st->temp_path);
                if (r < 0)
                        return log_oom();
        }

        (void) mkdir_parents_label(st->temp_path, 0700);

        if (FLAGS_SET(i->flags, IMPORT_FOREIGN_UID)) {
                r = import_make_foreign_userns(&i->userns_fd);
                if (r < 0)
                        return r;

                _cleanup_(sd_varlink_unrefp) sd_varlink *mountfsd_link = NULL;
                r = mountfsd_connect(&mountfsd_link);
                if (r < 0)
                        return log_error_errno(r, "Failed to connect to mountfsd: %m");

                _cleanup_close_ int directory_fd = -EBADF;
                r = mountfsd_make_directory(
                                mountfsd_link,
                                st->temp_path,
                                MODE_INVALID,
                                /* flags= */ 0,
                                &directory_fd);
                if (r < 0)
                        return log_error_errno(r, "Failed to make directory via mountfsd: %m");

                r = mountfsd_mount_directory_fd(
                                mountfsd_link,
                                directory_fd,
                                i->userns_fd,
                                DISSECT_IMAGE_FOREIGN_UID,
                                &st->tree_fd);
                if (r < 0)
                        return log_error_errno(r, "Failed to mount directory via mountsd: %m");
        } else {
                if (i->flags & IMPORT_BTRFS_SUBVOL)
                        r = btrfs_subvol_make_fallback(AT_FDCWD, st->temp_path, 0755);
                else
                        r = RET_NERRNO(mkdir(st->temp_path, 0755));
                if (r < 0)
                        return log_error_errno(r, "Failed to create directory/subvolume %s: %m", st->temp_path);

                if (r > 0 && (i->flags & IMPORT_BTRFS_QUOTA)) { /* actually btrfs subvol */
                        (void) import_assign_pool_quota_and_warn(i->image_root);
                        (void) import_assign_pool_quota_and_warn(st->temp_path);
                }

                st->tree_fd = open(st->temp_path, O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
                if (st->tree_fd < 0)
                        return log_error_errno(errno, "Failed to open '%s': %m", st->temp_path);
        }

        j->disk_fd = import_fork_tar_x(st->tree_fd, i->userns_fd, &st->tar_pid);
        if (j->disk_fd < 0)
                return j->disk_fd;

        return 0;
}

static void oci_layer_state_free_wrapper(void *p) {
        oci_layer_state_free(p);
}

typedef struct OciManifestLayer {
        char *media_type;
        struct iovec digest;
        uint64_t size;
} OciManifestLayer;

static void oci_manifest_layer_done(OciManifestLayer *layer) {
        assert(layer);

        layer->media_type = mfree(layer->media_type);
        iovec_done(&layer->digest);
}

static int oci_layer_dirname_for_digest(struct iovec *iovec, char **ret) {
        assert(iovec);
        assert(ret);

        _cleanup_free_ char *h = oci_digest_string(iovec);
        if (!h)
                return log_oom();

        _cleanup_free_ char *fn = strjoin(".oci-", h);
        if (!fn)
                return log_oom();

        *ret = TAKE_PTR(fn);
        return 0;
}

static int oci_pull_queue_layer(OciPull *i, OciManifestLayer *layer) {
        int r;

        assert(i);
        assert(layer);

        _cleanup_free_ char *url = NULL;
        r = oci_make_blob_url(i->protocol, i->repository, i->image, &layer->digest, &url);
        if (r < 0)
                return r;

        _cleanup_free_ char *fn = NULL;
        r = oci_layer_dirname_for_digest(&layer->digest, &fn);
        if (r < 0)
                return r;

        _cleanup_free_ char *final_path = path_join(i->image_root, fn);
        if (!final_path)
                return log_oom();

        r = is_dir(final_path, /* follow= */ true);
        if (r < 0) {
                if (r != -ENOENT)
                        return log_error_errno(r, "Failed to determine if directory '%s' exists: %m", final_path);
        } else {
                log_debug("Layer '%s' already exists, skipping download.", final_path);
                return 0;
        }

        _cleanup_(oci_layer_state_freep) OciLayerState *st = new(OciLayerState, 1);
        if (!st)
                return -ENOMEM;

        *st = (OciLayerState) {
                .pull = i,
                .tar_pid = PIDREF_NULL,
                .tree_fd = -EBADF,
                .final_path = TAKE_PTR(final_path),
        };

        /* Set up  */
        _cleanup_(pull_job_unrefp) PullJob *j = NULL;
        r = pull_job_new(&j, url, i->glue, st);
        if (r < 0)
                return r;

        j->free_userdata = oci_layer_state_free_wrapper;
        TAKE_PTR(st);

        r = pull_job_set_accept(j, STRV_MAKE(layer->media_type));
        if (r < 0)
                return r;

        if (i->bearer_token) {
                r = pull_job_set_bearer_token(j, i->bearer_token);
                if (r < 0)
                        return r;
        }

        j->on_finished = oci_pull_job_on_finished_layer;
        j->on_open_disk = oci_pull_job_on_open_disk;
        j->expected_content_length = layer->size;
        j->calc_checksum = true;
        if (!iovec_memdup(&layer->digest, &j->expected_checksum))
                return -ENOMEM;

        r = ordered_set_ensure_put(&i->queued_layer_jobs, &pull_job_hash_ops, j);
        if (r < 0)
                return r;

        TAKE_PTR(j);
        return 0;
}

static int json_dispatch_oci_manifest_layer(sd_json_variant *v, OciManifestLayer *layer) {
        int r;

        assert(v);
        assert(layer);

        static const struct sd_json_dispatch_field dispatch_table[] = {
                { "mediaType", SD_JSON_VARIANT_STRING,   sd_json_dispatch_string,      offsetof(OciManifestLayer, media_type), SD_JSON_MANDATORY },
                { "digest",    SD_JSON_VARIANT_STRING,   json_dispatch_oci_digest,     offsetof(OciManifestLayer, digest),     SD_JSON_MANDATORY },
                { "size",      SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uint64,      offsetof(OciManifestLayer, size),       SD_JSON_MANDATORY },
                {}
        };

        r = sd_json_dispatch(v, dispatch_table, SD_JSON_ALLOW_EXTENSIONS|SD_JSON_LOG, layer);
        if (r < 0)
                return r;

        if (!STR_IN_SET(layer->media_type,
                        "application/vnd.oci.image.layer.v1.tar",
                        "application/vnd.oci.image.layer.v1.tar+gzip",
                        "application/vnd.oci.image.layer.v1.tar+zstd")) {
                json_log(v, SD_JSON_LOG, /* error= */ 0, "Unexpected manifest layer with media type '%s', skipping.", layer->media_type);
                return 0;
        }

        return 1;
}

typedef struct OciManifestConfig {
        char *media_type;
        struct iovec digest;
        uint64_t size;
        struct iovec data;
} OciManifestConfig;

static void oci_manifest_config_done(OciManifestConfig *config) {
        assert(config);

        config->media_type = mfree(config->media_type);
        iovec_done(&config->digest);
        iovec_done(&config->data);
}

static int oci_pull_fetch_config(OciPull *i, OciManifestConfig *config) {
        int r;

        assert(i);
        assert(config);

        if (i->config_job)
                return log_error_errno(SYNTHETIC_ERRNO(EBUSY), "Two configs requested, refusing.");

        _cleanup_free_ char *url = NULL;
        r = oci_make_blob_url(i->protocol, i->repository, i->image, &config->digest, &url);
        if (r < 0)
                return r;

        _cleanup_free_ char *h = oci_digest_string(&config->digest);
        if (!h)
                return log_oom();

        r = pull_job_new(&i->config_job, url, i->glue, i);
        if (r < 0)
                return r;

        r = pull_job_set_accept(i->config_job, STRV_MAKE(config->media_type));
        if (r < 0)
                return r;

        if (i->bearer_token) {
                r = pull_job_set_bearer_token(i->config_job, i->bearer_token);
                if (r < 0)
                        return r;
        }

        i->config_job->on_finished = oci_pull_job_on_finished_config;
        i->config_job->expected_content_length = config->size;
        i->config_job->calc_checksum = true;
        if (!iovec_memdup(&config->digest, &i->config_job->expected_checksum))
                return log_oom();

        i->config_job->description = strjoin("Image configuration (", url, ")");

        r = pull_job_begin(i->config_job);
        if (r < 0)
                return r;

        return 0;
}

static int json_dispatch_oci_manifest_config(sd_json_variant *v, OciManifestConfig *config) {
        int r;

        assert(v);
        assert(config);

        static const struct sd_json_dispatch_field dispatch_table[] = {
                { "mediaType", SD_JSON_VARIANT_STRING,   sd_json_dispatch_string,      offsetof(OciManifestConfig, media_type), SD_JSON_MANDATORY },
                { "digest",    SD_JSON_VARIANT_STRING,   json_dispatch_oci_digest,     offsetof(OciManifestConfig, digest),     SD_JSON_MANDATORY },
                { "size",      SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uint64,      offsetof(OciManifestConfig, size),       SD_JSON_MANDATORY },
                { "data",      SD_JSON_VARIANT_STRING,   json_dispatch_unbase64_iovec, offsetof(OciManifestConfig, data),       0 },
                {}
        };

        r = sd_json_dispatch(v, dispatch_table, SD_JSON_ALLOW_EXTENSIONS|SD_JSON_LOG, config);
        if (r < 0)
                return r;

        if (!STR_IN_SET(config->media_type, "application/vnd.oci.image.config.v1+json")) {
                json_log(v, SD_JSON_LOG, /* error= */ 0, "Unexpected manifest config with media type '%s', skipping.", config->media_type);
                return 0;
        }

        if (iovec_is_set(&config->data)) {
                if (config->data.iov_len != config->size)
                        return json_log(v, SD_JSON_LOG, SYNTHETIC_ERRNO(EBADMSG), "Manifest config size mismatch.");

                uint8_t h[SHA256_DIGEST_SIZE];
                if (memcmp_nn(sha256_direct(config->data.iov_base, config->data.iov_len, h), SHA256_DIGEST_SIZE,
                              config->digest.iov_base, config->digest.iov_len) != 0)
                        return json_log(v, SD_JSON_LOG, SYNTHETIC_ERRNO(EBADMSG), "Manifest data size mismatch.");
        }

        return 1;
}

static int oci_pull_fetch_layers(OciPull *i) {
        int r;

        assert(i);

        while (set_size(i->active_layer_jobs) < ACTIVE_LAYERS_MAX) {
                _cleanup_(pull_job_unrefp) PullJob *j = ordered_set_steal_first(i->queued_layer_jobs);
                if (!j)
                        return 0;

                r = pull_job_begin(j);
                if (r < 0)
                        return r;

                r = set_ensure_put(&i->active_layer_jobs, &pull_job_hash_ops, j);
                if (r < 0)
                        return r;

                TAKE_PTR(j);
        }

        return 0;
}

static int oci_pull_process_manifest(OciPull *i, PullJob *j) {
        int r;

        assert(i);
        assert(j);

        /* Processes a just downloaded OCI image manifest, as per:
         *
         * https://github.com/opencontainers/image-spec/blob/main/manifest.md */

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        r = pull_job_payload_as_json(j, &v);
        if (r < 0)
                return r;

        struct {
                unsigned schema_version;
                const char *media_type;
                sd_json_variant *config;
                sd_json_variant *layers;
        } manifest_data = {
                .schema_version = UINT_MAX,
        };

        static const struct sd_json_dispatch_field dispatch_table[] = {
                { "schemaVersion", SD_JSON_VARIANT_INTEGER, sd_json_dispatch_uint,          voffsetof(manifest_data, schema_version), SD_JSON_MANDATORY },
                { "mediaType",     SD_JSON_VARIANT_STRING,  sd_json_dispatch_const_string,  voffsetof(manifest_data, media_type),     0                 },
                { "config",        SD_JSON_VARIANT_OBJECT,  sd_json_dispatch_variant_noref, voffsetof(manifest_data, config),         0                 },
                { "layers",        SD_JSON_VARIANT_ARRAY,   sd_json_dispatch_variant_noref, voffsetof(manifest_data, layers),         SD_JSON_MANDATORY },
                {}
        };

        r = sd_json_dispatch(v, dispatch_table, SD_JSON_ALLOW_EXTENSIONS|SD_JSON_LOG, &manifest_data);
        if (r < 0)
                return r;

        if (manifest_data.schema_version != 2)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "OCI image manifest has unsupported schema version %u, refusing.", manifest_data.schema_version);
        if (manifest_data.media_type && !streq(manifest_data.media_type, "application/vnd.oci.image.manifest.v1+json"))
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "OCI image manifest has unexpected media type '%s', refusing.", manifest_data.media_type);

        if (manifest_data.config) {
                _cleanup_(oci_manifest_config_done) OciManifestConfig config = {
                        .size = UINT64_MAX,
                };

                r = json_dispatch_oci_manifest_config(manifest_data.config, &config);
                if (r < 0)
                        return r;

                if (iovec_is_set(&config.data)) {
                        iovec_done(&i->config);
                        i->config = TAKE_STRUCT(config.data);
                } else {
                        r = oci_pull_fetch_config(i, &config);
                        if (r < 0)
                                return r;
                }
        }

        sd_json_variant *m;
        JSON_VARIANT_ARRAY_FOREACH(m, manifest_data.layers) {
                _cleanup_(oci_manifest_layer_done) OciManifestLayer layer = {
                        .size = UINT64_MAX,
                };

                r = json_dispatch_oci_manifest_layer(m, &layer);
                if (r < 0)
                        return r;
                if (r == 0) /* skip? */
                        continue;

                if (i->n_layers >= LAYER_MAX)
                        return log_error_errno(SYNTHETIC_ERRNO(E2BIG), "Too many layers in manifest (> %zu), refusing.", i->n_layers);

                if (!GREEDY_REALLOC(i->layer_digests, i->n_layers + 1))
                        return log_oom();

                if (!iovec_memdup(&layer.digest, i->layer_digests + i->n_layers))
                        return log_oom();

                i->n_layers++;

                r = oci_pull_queue_layer(i, &layer);
                if (r < 0)
                        return r;
        }

        if (i->n_layers == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EPROTO), "Manifest has no recognized file system layers, refusing.");

        assert(i->n_layers >= ordered_set_size(i->queued_layer_jobs));
        size_t present_layers = i->n_layers - ordered_set_size(i->queued_layer_jobs);

        log_info("Image %s/%s:%s has %zu layers, %zu already present.", i->repository, i->image, i->tag, i->n_layers, present_layers);

        /* Assign nice descriptions that indicate which layer we are talking of here */
        PullJob *q;
        size_t k = 0;
        ORDERED_SET_FOREACH(q, i->queued_layer_jobs) {
                _cleanup_free_ char *d = NULL;

                if (asprintf(&d, "Layer %zu/%zu (%s)", present_layers + k + 1, i->n_layers, q->url) < 0)
                        return log_oom();

                free_and_replace(q->description, d);
                k++;
        }

        return oci_pull_work(i);
}

static bool oci_pull_is_done(OciPull *i) {
        assert(i);
        assert(i->manifest_job);

        if (!PULL_JOB_IS_COMPLETE(i->manifest_job) ||
            (i->bearer_token_job && !PULL_JOB_IS_COMPLETE(i->bearer_token_job)) ||
            (i->config_job && !PULL_JOB_IS_COMPLETE(i->config_job)))
                return false;

        return ordered_set_isempty(i->queued_layer_jobs) &&
                set_isempty(i->active_layer_jobs);
}

typedef struct OciConfiguration {
        char *user;
        char **env;
        char **entrypoint;
        char **cmd;
        char *working_dir;
        int stop_signal;
} OciConfiguration;

static void oci_configuration_done(OciConfiguration *c) {
        assert(c);

        c->user = mfree(c->user);
        c->env = strv_free(c->env);
        c->entrypoint = strv_free(c->entrypoint);
        c->cmd = strv_free(c->cmd);
        c->working_dir = mfree(c->working_dir);
}

static int print_pair_escaped(FILE *f, const char *field, const char *value) {
        assert(f);
        assert(field);
        assert(value);

        _cleanup_free_ char *escaped = cescape(value);
        if (!escaped)
                return log_oom();

        fputs(field, f);
        fputc('=', f);
        fputs(escaped, f);
        fputc('\n', f);

        return 0;
}

static int dispatch_unsupported(const char *name, sd_json_variant *v, sd_json_dispatch_flags_t flags, void *userdata) {
        assert(v);
        json_log(v, flags|SD_JSON_WARNING, /* error= */ 0, "OCI image specification field '%s' cannot be be translated to any corresponding .nspawn setting, skipping.", name);
        return 0;
}

static int oci_pull_save_nspawn_settings(OciPull *i) {
        int r;

        assert(i);
        assert(iovec_is_set(&i->config));

        /* This translates the image spec "configuration" object into native .nspawn files for consumption by
         * systemd-nspawn. It's vaguely related to
         * https://github.com/opencontainers/image-spec/blob/v1.1.1/conversion.md except of course we don't
         * translate to the OCI runtime spec here but rather to .nspawn knobs. */

        /* The PullJob logic implicitly NUL terminates */
        assert(((char*) i->config.iov_base)[i->config.iov_len] == 0);

        if (memchr(i->config.iov_base, 0, i->config.iov_len))
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Embedded NUL by in JSON config data, refusing.");

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        unsigned line = 0, column = 0;
        r = sd_json_parse((char*) i->config.iov_base, /* flags= */ 0, &v, &line, &column);
        if (r < 0)
                return log_error_errno(r, "Failed to parse JSON config data at position %u:%u: %m", line, column);

        sd_json_variant *config = sd_json_variant_by_key(v, "config");

        _cleanup_(oci_configuration_done) OciConfiguration config_data = {
                .stop_signal = SIGTERM,
        };
        static const struct sd_json_dispatch_field dispatch_table[] = {
                { "User",         SD_JSON_VARIANT_STRING,        json_dispatch_user_group_name,  offsetof(OciConfiguration, user),        0 },
                { "Env",          SD_JSON_VARIANT_ARRAY,         json_dispatch_strv_environment, offsetof(OciConfiguration, env),         0 },
                { "Entrypoint",   SD_JSON_VARIANT_ARRAY,         sd_json_dispatch_strv,          offsetof(OciConfiguration, entrypoint),  0 },
                { "Cmd",          SD_JSON_VARIANT_ARRAY,         sd_json_dispatch_strv,          offsetof(OciConfiguration, cmd),         0 },
                { "WorkingDir",   SD_JSON_VARIANT_STRING,        json_dispatch_path,             offsetof(OciConfiguration, working_dir), 0 },
                { "StopSignal",   SD_JSON_VARIANT_STRING,        sd_json_dispatch_signal,        offsetof(OciConfiguration, stop_signal), 0 },

                /* Currently unsupported fields that the OCI image spec defines but we cannot convert into
                 * .nspawn settings just yet. */
                { "ExposedPorts", _SD_JSON_VARIANT_TYPE_INVALID, dispatch_unsupported,           0,                                       0 },
                { "Volumes",      _SD_JSON_VARIANT_TYPE_INVALID, dispatch_unsupported,           0,                                       0 },
                { "Labels",       _SD_JSON_VARIANT_TYPE_INVALID, dispatch_unsupported,           0,                                       0 },
                { "ArgsEscaped",  _SD_JSON_VARIANT_TYPE_INVALID, dispatch_unsupported,           0,                                       0 },
                { "Memory",       _SD_JSON_VARIANT_TYPE_INVALID, dispatch_unsupported,           0,                                       0 },
                { "MemorySwap",   _SD_JSON_VARIANT_TYPE_INVALID, dispatch_unsupported,           0,                                       0 },
                { "CpuShares",    _SD_JSON_VARIANT_TYPE_INVALID, dispatch_unsupported,           0,                                       0 },
                { "Healthcheck",  _SD_JSON_VARIANT_TYPE_INVALID, dispatch_unsupported,           0,                                       0 },
                {}
        };

        r = sd_json_dispatch(config, dispatch_table, SD_JSON_ALLOW_EXTENSIONS|SD_JSON_LOG, &config_data);
        if (r < 0)
                return r;

        _cleanup_free_ char *fn = strjoin(i->local, ".nspawn");
        if (!fn)
                return log_oom();

        _cleanup_free_ char *j = path_join(i->image_root, fn);
        if (!fn)
                return log_oom();

        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_(unlink_and_freep) char *tmpfile = NULL;
        r = fopen_tmpfile_linkable(j, O_WRONLY|O_CLOEXEC, &tmpfile, &f);
        if (r < 0)
                return log_error_errno(r, "Failed to create '%s': %m", j);

        fprintf(f,
                "# Generated from OCI configuration object\n"
                "[Exec]\n"
                "Boot=no\n"
                "KillSignal=%s\n",
                signal_to_string(config_data.stop_signal));

        if (config_data.user && !STR_IN_SET(config_data.user, "root", "0")) {
                r = print_pair_escaped(f, "User", config_data.user);
                if (r < 0)
                        return r;
        }

        if (config_data.working_dir && !path_equal(config_data.working_dir, "/")) {
                r = print_pair_escaped(f, "WorkingDirectory", config_data.working_dir);
                if (r < 0)
                        return r;
        }

        STRV_FOREACH(e, config_data.env) {
                r = print_pair_escaped(f, "Environment", *e);
                if (r < 0)
                        return r;
        }

        _cleanup_strv_free_ char **cmdline = strv_copy(config_data.entrypoint);
        if (!cmdline)
                return log_oom();
        if (strv_extend_strv(&cmdline, config_data.cmd, /* filter_duplicates= */ false) < 0)
                return log_oom();

        if (!strv_isempty(cmdline)) {
                _cleanup_free_ char *ej = NULL;

                STRV_FOREACH(z, cmdline) {
                        _cleanup_free_ char *q = NULL;
                        const char *a;

                        if (isempty(*z))
                                a = "\"\"";
                        else if (!in_charset(*z, ALPHANUMERICAL "=+-_/;.:,;")) {
                                _cleanup_free_ char *e = shell_escape(*z, "\"");
                                if (!e)
                                        return log_oom();

                                q = strjoin("\"", e, "\"");
                                if (!q)
                                        return log_oom();

                                a = q;
                        } else
                                a = *z;

                        if (!strextend_with_separator(&ej, " ", a))
                                return log_oom();
                }

                fprintf(f, "Parameters=%s\n", ej);
        }

        r = flink_tmpfile(f, tmpfile, j, LINK_TMPFILE_REPLACE);
        if (r < 0)
                return log_error_errno(r, "Failed to move '%s' into place: %m", j);

        log_info("systemd-nspawn settings file written to '%s'.", j);
        return 0;
}

static int oci_pull_save_oci_config(OciPull *i) {
        int r;

        assert(i);
        assert(iovec_is_set(&i->config));

        _cleanup_free_ char *fn = strjoin(i->local, ".oci-config");
        if (!fn)
                return log_oom();

        _cleanup_free_ char *j = path_join(i->image_root, fn);
        if (!fn)
                return log_oom();

        _cleanup_close_ int fd = -EBADF;
        _cleanup_(unlink_and_freep) char *tmpfile = NULL;
        fd = open_tmpfile_linkable(j, O_WRONLY|O_CLOEXEC, &tmpfile);
        if (fd < 0)
                return log_error_errno(fd, "Failed to create '%s': %m", j);

        r = loop_write(fd, i->config.iov_base, i->config.iov_len);
        if (r < 0)
                return log_error_errno(r, "Failed to write '%s': %m", j);

        r = link_tmpfile(fd, tmpfile, j, LINK_TMPFILE_REPLACE);
        if (r < 0)
                return log_error_errno(r, "Failed to move '%s' into place: %m", j);

        log_info("OCI config written to '%s'.", j);
        return 0;
}

static int oci_pull_save_mstack(OciPull *i) {
        int r;

        assert(i);

        _cleanup_free_ char *dn = strjoin(i->local, ".mstack");
        if (!dn)
                return log_oom();

        _cleanup_free_ char *j = path_join(i->image_root, dn);
        if (!dn)
                return log_oom();

        log_notice("Creating '%s'", j);

        _cleanup_free_ char *_jt = NULL;
        r = tempfn_random(j, "oci", &_jt);
        if (r < 0)
                return log_oom();

        _cleanup_close_ int dir_fd = xopenat(AT_FDCWD, _jt, O_DIRECTORY|O_CREAT|O_CLOEXEC);
        if (dir_fd < 0)
                return log_error_errno(dir_fd, "Failed to create '%s': %m", j);

        _cleanup_(rm_rf_physical_and_freep) char *jt = TAKE_PTR(_jt);
        for (size_t k = 0; k < i->n_layers; k++) {
                _cleanup_free_ char *sl = NULL;
                if (asprintf(&sl, "layer@%zu", k) < 0)
                        return log_oom();

                _cleanup_free_ char *ldn = NULL;
                if (oci_layer_dirname_for_digest(i->layer_digests + k, &ldn) < 0)
                        return log_oom();

                _cleanup_free_ char *with_dot_dot = path_join("..", ldn);
                if (!with_dot_dot)
                        return log_oom();

                if (symlinkat(with_dot_dot, dir_fd, sl) < 0)
                        return log_error_errno(errno, "Failed to make symlink for layer '%s': %m", sl);
        }

        if (!FLAGS_SET(i->flags, IMPORT_READ_ONLY)) {
                /* If this shall be a mutable container let's also create an "rw" layer, that will become
                 * the upper layer in the overlayfs stack. */

                if (FLAGS_SET(i->flags, IMPORT_FOREIGN_UID)) {
                        r = import_make_foreign_userns(&i->userns_fd);
                        if (r < 0)
                                return r;

                        r = mountfsd_make_directory_fd(
                                        /* vl= */ NULL,
                                        dir_fd,
                                        "rw",
                                        0755,
                                        /* flags= */ 0,
                                        /* ret_directory_fd= */ NULL);
                        if (r < 0)
                                return r;
                } else {
                        _cleanup_close_ int rw_fd = open_mkdir_at(dir_fd, "rw", O_EXCL|O_CLOEXEC, 0755);
                        if (rw_fd < 0)
                                return log_error_errno(rw_fd, "Failed to create 'rw' layer: %m");
                }
        }

        if (rename(jt, j) < 0)
                return log_error_errno(errno, "Failed to move '%s' into place: %m", j);

        jt = mfree(jt); /* Disarm rm_rf_physical_and_free() */

        log_info("Mount stack written to '%s'.", j);
        return 0;
}

static int oci_pull_make_local(OciPull *i) {
        int r;

        assert(i);
        assert(oci_pull_is_done(i));

        r = oci_pull_save_mstack(i);
        if (r < 0)
                return r;

        if (!iovec_is_set(&i->config) ||
            iovec_memcmp(&i->config, &IOVEC_MAKE_STRING("{}")) == 0)
                log_info("Image has no configuration, not saving.");
        else {
                r = oci_pull_save_nspawn_settings(i);
                if (r < 0)
                        return r;

                r = oci_pull_save_oci_config(i);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int oci_pull_work(OciPull *i) {
        int r;

        assert(i);

        r = oci_pull_fetch_layers(i);
        if (r < 0)
                return r;

        if (!oci_pull_is_done(i))
                return 1; /* continue */

        r = oci_pull_make_local(i);
        if (r < 0)
                return r;

        log_info("Everything done.");
        return 0; /* done */
}

static void oci_pull_finish(OciPull *i, int r) {
        assert(i);

        if (i->on_finished)
                i->on_finished(i, r, i->userdata);
        else
                sd_event_exit(i->event, r);
}

static void oci_pull_job_on_finished_layer(PullJob *j) {
        int r;

        assert(j);

        OciLayerState *st = ASSERT_PTR(j->userdata);
        OciPull *i = st->pull;

        if (j->error != 0) {
                r = log_error_errno(j->error, "Failed to retrieve layer file: %m");
                goto finish;
        }

        pull_job_close_disk_fd(j);

        if (pidref_is_set(&st->tar_pid)) {
                r = pidref_wait_for_terminate_and_check("tar", &st->tar_pid, WAIT_LOG);
                if (r < 0)
                        goto finish;

                pidref_done(&st->tar_pid);
                if (r != EXIT_SUCCESS) {
                        r = -EIO;
                        goto finish;
                }
        }

        assert(st->temp_path);
        assert(st->final_path);

        r = install_file(AT_FDCWD, st->temp_path,
                         AT_FDCWD, st->final_path,
                         INSTALL_READ_ONLY|INSTALL_GRACEFUL);
        if (r < 0) {
                log_error_errno(r, "Failed to rename final image name to %s: %m", st->final_path);
                goto finish;
        }

        st->temp_path = mfree(st->temp_path);

        r = set_ensure_put(&i->done_layer_jobs, &pull_job_hash_ops, j);
        if (r < 0) {
                log_oom();
                goto finish;
        }

        assert(set_remove(i->active_layer_jobs, j) == j);

        r = oci_pull_work(i);
        if (r <= 0)
                goto finish;

        return;

finish:
        oci_pull_finish(i, r);
}

static void oci_pull_job_on_finished_config(PullJob *j) {
        int r;

        assert(j);
        OciPull *i = ASSERT_PTR(j->userdata);
        assert(i->config_job == j);

        if (j->error != 0) {
                if (j->error == -ENOMEDIUM) /* HTTP 404 */
                        r = log_error_errno(j->error, "Failed to retrieve config object. (Wrong URL?)");
                else
                        r = log_error_errno(j->error, "Failed to retrieve config object: %m");
                goto finish;
        }

        iovec_done(&i->config);
        i->config = TAKE_STRUCT(j->payload);

        r = oci_pull_work(i);
        if (r <= 0)
                goto finish;

        return;

finish:
        oci_pull_finish(i, r);
}

static void oci_pull_job_on_finished_bearer_token(PullJob *j) {
        int r;

        assert(j);
        OciPull *i = ASSERT_PTR(j->userdata);
        assert(i->bearer_token_job == j);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

        if (j->error != 0) {
                if (j->error == -ENOMEDIUM) /* HTTP 404 */
                        r = log_error_errno(j->error, "Failed to retrieve bearer token. (Wrong URL?)");
                else
                        r = log_error_errno(j->error, "Failed to retrieve bearer token: %m");
                goto finish;
        }

        r = pull_job_payload_as_json(j, &v);
        if (r < 0)
                goto finish;

        sd_json_variant *tv = sd_json_variant_by_key(v, "token");
        if (!tv) {
                r = log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Bearer token lacks 'token' field.");
                goto finish;
        }

        if (!sd_json_variant_is_string(tv)) {
                r = log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "'token' field of bearer token is not a string.");
                goto finish;
        }

        r = free_and_strdup_warn(&i->bearer_token, sd_json_variant_string(tv));
        if (r < 0)
                goto finish;

        assert(i->manifest_job);
        r = pull_job_set_bearer_token(i->manifest_job, i->bearer_token);
        if (r < 0) {
                log_error_errno(r, "Failed to set bearer token on manifest job: %m");
                goto finish;
        }

        r = pull_job_restart(i->manifest_job, /* new_url= */ NULL);
        if (r < 0)
                goto finish;

        return;

finish:
        oci_pull_finish(i, r);
}

static int make_bearer_token_url(const char *realm, const char *service, const char *scope, char **ret) {
        assert(realm);
        assert(service);
        assert(scope);
        assert(ret);

        _cleanup_free_ char *rs = urlescape(service);
        if (!rs)
                return -ENOMEM;

        _cleanup_free_ char *ss = urlescape(scope);
        if (!ss)
                return -ENOMEM;

        _cleanup_free_ char *url = strjoin(realm, "?service=", rs, "&scope=", ss);
        if (!url)
                return -ENOMEM;

        *ret = TAKE_PTR(url);
        return 0;
}

static int oci_pull_process_authentication_challenge(OciPull *i, const char *challenge) {
        int r;

        assert(i);
        assert(challenge);

        /* We only know what to do with the bearer token challenge */
        const char *e = startswith_no_case(challenge, "bearer ");
        if (!e)
                return log_error_errno(SYNTHETIC_ERRNO(ENOKEY), "Authentication mechanism not recognized, cannot authenticate.");

        if (i->bearer_token_job)
                return log_error_errno(SYNTHETIC_ERRNO(EBUSY), "Two bearer token challenges requested, refusing.");

        e += strspn(e, WHITESPACE);

        _cleanup_strv_free_ char **l = NULL;
        r = strv_split_full(&l, e, ",", EXTRACT_KEEP_QUOTE);
        if (r < 0)
                return log_error_errno(r, "Failed to split bearer token paramaters: %m");

        _cleanup_free_ char *realm = NULL, *scope = NULL, *service = NULL;
        struct {
                const char *name;
                char **value;
        } fields[] = {
                { "realm=\"",   &realm   },
                { "scope=\"",   &scope   },
                { "service=\"", &service },
        };

        STRV_FOREACH(k, l) {
                bool found = false;

                FOREACH_ELEMENT(f, fields) {
                        const char *v = startswith_no_case(*k, f->name);
                        if (!v)
                                continue;

                        const char *q = endswith(v,"\"");
                        if (!q) {
                                log_warning("Field isn't quoted properly: %s", *k);
                                continue;
                        }

                        _cleanup_free_ char *s = strndup(v, q - v);
                        if (!s)
                                return log_oom();

                        free_and_replace(*f->value, s);
                        found = true;
                        break;
                }

                if (!found)
                        log_debug("Ignoring bearer token challenge field: %s", *k);
        }

        if (!realm || !service || !scope)
                return log_error_errno(SYNTHETIC_ERRNO(ENOKEY), "Incomplete bearer token fields");

        if (!startswith_no_case(realm, "https://"))
                return log_error_errno(SYNTHETIC_ERRNO(ENOKEY), "Authentication realm is not an URL, don't know how to proceed.");

        _cleanup_free_ char *url = NULL;
        r = make_bearer_token_url(realm, service, scope, &url);
        if (r < 0)
                return log_error_errno(r, "Failed to make bearer token URL: %m");

        r = pull_job_new(&i->bearer_token_job, url, i->glue, i);
        if (r < 0)
                return r;

        i->bearer_token_job->on_finished = oci_pull_job_on_finished_bearer_token;
        i->bearer_token_job->description = strjoin("Bearer token (", url, ")");

        r = pull_job_begin(i->bearer_token_job);
        if (r < 0)
                return r;

        return 1; /* continue running */
}

static void oci_pull_job_on_finished_manifest(PullJob *j) {
        int r;

        assert(j);
        OciPull *i = ASSERT_PTR(j->userdata);
        assert(i->manifest_job == j);

        if (j->error != 0) {
                if (j->error == -ENOMEDIUM) /* HTTP 404 */
                        r = log_error_errno(j->error, "Failed to retrieve manifest/index file. (Wrong URL?)");
                else if (j->error == -ENOKEY) { /* HTTP 401 - Need authentication */

                        if (j->authentication_challenge) {
                                r = oci_pull_process_authentication_challenge(i, j->authentication_challenge);
                                if (r > 0)
                                        return;

                                goto finish;
                        } else
                                r = log_error_errno(j->error, "Failed to retrieve manifest/index file. (Needing authentication.)");
                } else
                        r = log_error_errno(j->error, "Failed to retrieve manifest/index file: %m");
                goto finish;
        }

        /* If we have no content type, let's assume it's a manifest, not an index. This can happen in case we
         * operate with file:// URLs, which in turn is really useful for testing purposes, to mock an OCI
         * registry without having to set up an HTTP service. */
        if (streq_ptr(j->content_type, "application/vnd.oci.image.manifest.v1+json") ||
            !j->content_type) {
                r = oci_pull_process_manifest(i, j);
                if (r <= 0)
                        goto finish;

                return;
        }

        if (streq_ptr(j->content_type, "application/vnd.oci.image.index.v1+json")) {

                if (i->refuse_index) {
                        r = log_error_errno(SYNTHETIC_ERRNO(EPROTO), "Already processed an OCI index, refusing to process another one.");
                        goto finish;
                }

                /* For now do not allow nested indexes */
                i->refuse_index = true;

                r = oci_pull_process_index(i, j);
                if (r <= 0)
                        goto finish;

                return;
        }

        r = log_error_errno(SYNTHETIC_ERRNO(EPROTO), "Unexpected content type '%s', refusing.", strna(j->content_type));

finish:
        oci_pull_finish(i, r);
}

int oci_pull_start(
                OciPull *i,
                const char *ref,
                const char *local,
                ImportFlags flags) {

        int r;

        assert(i);
        assert(ref);

        r = oci_ref_parse(ref, &i->repository, &i->image, &i->tag);
        if (r < 0)
                return r;

        r = oci_ref_normalize(&i->protocol, &i->repository, &i->image, &i->tag);
        if (r < 0)
                return r;

        if (local && !pull_validate_local(local, flags))
                return -EINVAL;

        if (i->manifest_job)
                return -EBUSY;

        r = free_and_strdup(&i->local, local);
        if (r < 0)
                return r;

        i->flags = flags;

        _cleanup_free_ char *url = NULL;
        r = oci_make_manifest_url(i->protocol, i->repository, i->image, i->tag, &url);
        if (r < 0)
                return r;

        /* Set up  */
        r = pull_job_new(&i->manifest_job, url, i->glue, i);
        if (r < 0)
                return r;

        if (i->bearer_token) {
                r = pull_job_set_bearer_token(i->manifest_job, i->bearer_token);
                if (r < 0)
                        return r;
        }

        r = pull_job_set_accept(
                        i->manifest_job,
                        STRV_MAKE("application/vnd.oci.image.manifest.v1+json",
                                  "application/vnd.oci.image.index.v1+json"));
        if (r < 0)
                return r;

        i->manifest_job->on_finished = oci_pull_job_on_finished_manifest;
        i->manifest_job->description = strjoin("Image Index (", url, ")");
        if (!i->manifest_job->description)
                return -ENOMEM;

        return pull_job_begin(i->manifest_job);
}
