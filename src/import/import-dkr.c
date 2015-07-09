/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2015 Codethink Limited

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

#include "import-dkr.h"
#include "sd-daemon.h"
#include "untar-job.h"
#include "rm-rf.h"
#include "util.h"
#include "strv.h"
#include "mkdir.h"
#include "btrfs-util.h"
#include "aufs-util.h"
#include "import-common.h"
#include "json.h"
#include "fileio.h"
#include "ratelimit.h"

struct DkrImport {
        sd_event *event;
        char *image_root;
        DkrImportFinished on_finished;
        void *userdata;

        char *local;
        bool force_local;
        bool read_only;

        UnTarJob *save_extract;
        UnTarJob *layer_extract;

        char **ancestry;
        unsigned n_ancestry;
        unsigned current_ancestry;

        char *temp_path;
        char *final_path;

        unsigned last_percent;
        RateLimit progress_rate_limit;
};

DkrImport *dkr_import_unref(DkrImport *i) {
        if (!i)
                return NULL;

        sd_event_unref(i->event);

        free(i->local);

        if (i->save_extract && i->save_extract->path)
                (void) rm_rf(i->save_extract->path, REMOVE_ROOT|REMOVE_PHYSICAL|REMOVE_SUBVOLUME);
        i->save_extract = untar_job_unref(i->save_extract);
        i->layer_extract = untar_job_unref(i->layer_extract);

        strv_free(i->ancestry);

        if (i->temp_path) {
                (void) rm_rf(i->temp_path, REMOVE_ROOT|REMOVE_PHYSICAL|REMOVE_SUBVOLUME);
                free(i->temp_path);
        }
        free(i->final_path);
        free(i);

        return NULL;
}

int dkr_import_new(
                DkrImport **ret,
                sd_event *event,
                const char *image_root,
                DkrImportFinished on_finished,
                void *userdata) {
        _cleanup_(dkr_import_unrefp) DkrImport *i = NULL;
        int r;

        assert(ret);

        i = new0(DkrImport, 1);
        if (!i)
                return -ENOMEM;

        i->last_percent = (unsigned) -1;
        RATELIMIT_INIT(i->progress_rate_limit, 100 * USEC_PER_MSEC, 1);

        if (event)
                i->event = sd_event_ref(event);
        else {
                r = sd_event_default(&i->event);
                if (r < 0)
                        return r;
        }
        i->image_root = strdup(image_root ?: "/var/lib/machines");
        if (!i->image_root)
                return -ENOMEM;
        i->on_finished = on_finished;
        i->userdata = userdata;

        *ret = i;
        i = NULL;

        return 0;
}

typedef enum DkrImportProgress {
        DKR_IMPORT_SAVEEXTRACT,
        DKR_IMPORT_LAYEREXTRACT,
        DKR_IMPORT_COPYING,
} DkrImportProgress;

static void dkr_import_report_progress(DkrImport *i, DkrImportProgress p, unsigned stage_percent) {
        unsigned total_percent;
        assert(i);

        switch (p) {

        case DKR_IMPORT_SAVEEXTRACT:
                total_percent = 0;
                total_percent += stage_percent * 5 / 100;
                break;

        case DKR_IMPORT_LAYEREXTRACT:
                total_percent = 20;
                total_percent += 75 * i->current_ancestry / MAX(1U, i->n_ancestry);
                total_percent += stage_percent * 75 / MAX(1U, i->n_ancestry) / 100;
                break;

        case DKR_IMPORT_COPYING:
                total_percent = 95;
                break;

        default:
                assert_not_reached("Unknown progress state");
        }

        if (total_percent == i->last_percent)
                return;

        if (!ratelimit_test(&i->progress_rate_limit))
                return;

        sd_notifyf(false, "X_IMPORT_PROGRESS=%u", total_percent);
        log_debug("Combined progress %u%%", total_percent);

        i->last_percent = total_percent;
}

static void dkr_tar_import_on_progress(UnTarJob *j, unsigned percent) {
        DkrImport *i;

        assert(j);
        assert(j->userdata);

        i = j->userdata;
        assert(IN_SET(j, i->save_extract, i->layer_extract));

        dkr_import_report_progress(
                        i,
                        j == i->save_extract ? DKR_IMPORT_SAVEEXTRACT :
                                               DKR_IMPORT_LAYEREXTRACT,
                        percent);
}

static int dkr_tar_import_on_read(UnTarJob *j) {
        DkrImport *i;
        int r = 0;

        assert(j);
        assert(j->userdata);

        i = j->userdata;
        assert(IN_SET(j, i->save_extract, i->layer_extract));

        r = loop_write(j->tar_fd, j->buffer, j->buffer_size, false);

        return r;
}

static const char *dkr_import_current_layer(const DkrImport *i) {
        assert(i);
        if (strv_isempty(i->ancestry))
                return NULL;

        return i->ancestry[i->current_ancestry];
}

static const char *dkr_import_current_base_layer(const DkrImport *i) {
        assert(i);

        if (strv_isempty(i->ancestry))
                return NULL;

        if (i->current_ancestry <= 0)
                return NULL;

        return i->ancestry[i->current_ancestry-1];
}

static bool dkr_import_is_done(DkrImport *i) {
        assert(i);
        assert(i->save_extract);
        assert(i->ancestry);
        assert(i->n_ancestry > 0);

        if (i->n_ancestry == 0)
                return false;

        if (i->ancestry[i->current_ancestry])
                return false;

        return true;
}

static int dkr_import_prepare_temp_volume(const DkrImport *i, const char *final_path, char **temp_path) {
        _cleanup_free_ char *temp = NULL;
        const char *base;
        int r;
        assert(i);

        r = tempfn_random(final_path, NULL, &temp);
        if (r < 0)
                return log_oom();

        r = mkdir_parents_label(temp, 0700);
        if (r < 0)
                return r;

        base = dkr_import_current_base_layer(i);
        if (base) {
                auto const char *base_path;

                base_path = strjoina(i->image_root, "/.dkr-", base, NULL);
                r = btrfs_subvol_snapshot(base_path, temp, BTRFS_SNAPSHOT_FALLBACK_COPY);
        } else
                r = btrfs_subvol_make(temp);
        if (r < 0)
                return log_error_errno(r, "Failed to make btrfs subvolume %s: %m", temp);

        *temp_path = temp;
        temp = NULL;

        return 0;
}

static void dkr_tar_import_on_finished(UnTarJob *j, int error);

static int dkr_import_enqueue_layer(DkrImport *i) {
        _cleanup_free_ char *final_path = NULL, *temp_path = NULL;
        const char *layer = NULL;
        auto const char *tar_path = NULL;
        _cleanup_close_ int fd = -1;
        int r;

        assert(i);
        assert(i->image_root);
        assert(i->save_extract);
        assert(i->save_extract->path);

        /* TODO: More or less identical to dkr_pull_pull_layer, unify. */
        for (;;) {
                layer = dkr_import_current_layer(i);
                if (!layer)
                        return 0;

                final_path = strjoin(i->image_root, "/.dkr-", layer, NULL);
                if (!final_path)
                        return log_oom();

                if (laccess(final_path, F_OK) < 0) {
                        if (errno == ENOENT)
                                break;

                        return log_error_errno(errno, "Failed to check for container: %m");
                }

                log_info("Layer %s already exists, skipping.", layer);

                i->current_ancestry++;

                free(final_path);
                final_path = NULL;
        }

        log_info("Importing layer %s...", layer);

        tar_path = strjoina(i->save_extract->path, "/", layer, "/layer.tar");

        r = dkr_import_prepare_temp_volume(i, final_path, &temp_path);
        if (r < 0)
                return r;

        fd = open(tar_path, O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (fd < 0)
                return -errno;

        r = untar_job_new(&i->layer_extract, i->event, dkr_tar_import_on_read, dkr_tar_import_on_progress, dkr_tar_import_on_finished, i);
        if (r < 0)
                return r;

        r = untar_job_begin(i->layer_extract, fd, temp_path);
        if (r < 0)
                return r;

        fd = -1;
        i->final_path = final_path;
        final_path = NULL;
        i->temp_path = temp_path;
        temp_path = NULL;

        return 0;
}

static int dkr_import_finish_layer(DkrImport *i) {
        int r;

        assert(i);

        r = aufs_resolve(i->temp_path);
        if (r < 0) {
                log_error_errno(r, "Failed to resolve aufs whiteouts: %m");
                return r;
        }

        r = btrfs_subvol_set_read_only(i->temp_path, true);
        if (r < 0) {
                log_error_errno(r, "Failed to mark snapshot read-only: %m");
                return r;
        }

        if (rename(i->temp_path, i->final_path) < 0) {
                log_error_errno(errno, "Failed to rename snaphsot: %m");
                return r;
        }

        log_info("Completed writing to layer %s.", i->final_path);

        i->layer_extract = untar_job_unref(i->layer_extract);
        free(i->temp_path);
        i->temp_path = NULL;
        free(i->final_path);
        i->final_path = NULL;

        i->current_ancestry++;

        return 0;
}

static int parse_repositories_manifest(char **id_out, const char *path) {
        auto const char *filename;
        int r;
        _cleanup_free_ char *contents = NULL;
        size_t size = 0;
        _cleanup_json_variant_unref_ JsonVariant *doc = NULL;
        char *original_name = NULL;
        JsonVariant *version_map = NULL, *id_variant = NULL;

        filename = strjoina(path, "/repositories", NULL);

        r = read_full_file(filename, &contents, &size);
        if (r < 0)
                return r;

        r = json_parse(contents, &doc);
        if (r < 0 || doc->type != JSON_VARIANT_OBJECT)
                return -EINVAL;
        assert(doc->size == 2);

        original_name = json_variant_string(&doc->objects[0]);
        version_map = json_variant_value(doc, original_name);
        if (version_map->type != JSON_VARIANT_OBJECT)
                return -EINVAL;

        id_variant = json_variant_value(version_map, "latest");
        if (!id_variant || id_variant->type != JSON_VARIANT_STRING)
                return -EINVAL;

        return free_and_strdup(id_out, json_variant_string(id_variant));
}

static int parse_parent_id(char **parent_out, const char *path, char *id) {
        auto const char *filename;
        int r;
        _cleanup_free_ char *contents = NULL;
        size_t size = 0;
        _cleanup_json_variant_unref_ JsonVariant *doc = NULL;
        JsonVariant *e = NULL;

        filename = strjoina(path, "/", id, "/json");

        r = read_full_file(filename, &contents, &size);
        if (r < 0)
                return r;

        r = json_parse(contents, &doc);
        if (r < 0 || doc->type != JSON_VARIANT_OBJECT)
                return -EINVAL;

        e = json_variant_value(doc, "parent");
        if (!e)
                return free_and_strdup(parent_out, NULL);

        if (e->type != JSON_VARIANT_STRING)
                return -EINVAL;

        return free_and_strdup(parent_out, json_variant_string(e));
}

static int parse_ancestry(char ***ancestry_out, unsigned *n_ancestry_out, const char *path) {
        int r;
        _cleanup_free_ char *leaf_id = NULL, *layer_id = NULL;
        _cleanup_strv_free_ char **ancestry = NULL;
        unsigned n_ancestry;

        assert(ancestry_out);
        assert(n_ancestry_out);
        assert(path);

        r = parse_repositories_manifest(&leaf_id, path);
        if (r < 0) {
                log_error_errno(r, "Invalid JSON repositories manifest");
                return r;
        }

        layer_id = strdup(leaf_id);
        if (!layer_id) {
                return -ENOMEM;
        }

        while (layer_id) {
                /* WIP NOTE: Could steal the reference here rather than
                   copying, but I think this makes it easier to reason
                   about the lifetimes. */
                r = strv_extend(&ancestry, layer_id);
                if (r < 0)
                        return r;

                r = parse_parent_id(&layer_id, path, layer_id);
                if (r < 0) {
                        log_error_errno(r, "Invalid JSON layer manifest for layer %s", layer_id);
                        return r;
                }
        }

        ancestry = strv_reverse(strv_uniq(ancestry));
        n_ancestry = strv_length(ancestry);

        strv_free(*ancestry_out);
        *ancestry_out = ancestry;
        ancestry = NULL;
        *n_ancestry_out = n_ancestry;

        return 0;
}

static void dkr_tar_import_on_finished(UnTarJob *j, int error) {
        DkrImport *i;
        int r;

        assert(j);
        assert(j->userdata);

        i = j->userdata;
        if (error != 0) {
                if (j == i->save_extract)
                        log_error_errno(error, "Failed to unpack layer bundle tar.");
                else if (j == i->layer_extract)
                        log_error_errno(error, "Failed to import layer");

                r = error;
                goto finish;
        }

        if (j == i->save_extract) {
                /* Parse layer metadata */
                r = parse_ancestry(&i->ancestry, &i->n_ancestry, j->path);
                if (r < 0)
                        goto finish;
                i->current_ancestry = 0;

                dkr_import_report_progress(i, DKR_IMPORT_LAYEREXTRACT, 0);
                r = untar_job_new(&i->layer_extract, i->event, dkr_tar_import_on_read, dkr_tar_import_on_progress, dkr_tar_import_on_finished, i);
                if (r < 0)
                        goto finish;

                r = dkr_import_enqueue_layer(i);
                if (r < 0)
                        goto finish;
        } else if (j == i->layer_extract) {
                r = dkr_import_finish_layer(i);
                if (r < 0)
                        goto finish;

                r = dkr_import_enqueue_layer(i);
                if (r < 0)
                        goto finish;
        } else
                assert_not_reached("Got finished event for unknown untar");

        if (!dkr_import_is_done(i))
                return;

        assert(i->local);
        assert(!i->final_path);
        assert(!strv_isempty(i->ancestry));

        i->final_path = strjoin(i->image_root, "/.dkr-", i->ancestry[i->n_ancestry - 1], NULL);
        if (!i->final_path) {
                r = log_oom();
                goto finish;
        }

        dkr_import_report_progress(i, DKR_IMPORT_COPYING, 0);
        r = import_make_local_copy(i->final_path, i->image_root, i->local, i->force_local);
        if (r < 0)
                goto finish;

        (void) rm_rf(i->save_extract->path, REMOVE_ROOT|REMOVE_PHYSICAL|REMOVE_SUBVOLUME);
        i->save_extract = untar_job_unref(i->save_extract);

        r = 0;
finish:
        if (i->on_finished)
                i->on_finished(i, r, i->userdata);
        else
                sd_event_exit(i->event, r);
}

int dkr_import_start(DkrImport *i, int fd, const char *local, bool force_local, bool read_only) {
        int r;
        auto char *temp_path = NULL;

        assert(i);
        assert(fd >= 0);
        assert(local);

        r = free_and_strdup(&i->local, local);
        if (r < 0)
                return r;
        i->force_local = force_local;
        i->read_only = read_only;

        r = untar_job_new(&i->save_extract, i->event, dkr_tar_import_on_read, dkr_tar_import_on_progress, dkr_tar_import_on_finished, i);
        if (r < 0)
                return r;

        i->ancestry = strv_free(i->ancestry);
        i->n_ancestry = i->current_ancestry = 0;

        temp_path = strjoina(secure_getenv("TMPDIR") ?: "/tmp", "/tmp.import-dkr.XXXXXX", NULL);
        if (!mkdtemp(temp_path))
                return -errno;

        dkr_import_report_progress(i, DKR_IMPORT_SAVEEXTRACT, 0);
        return untar_job_begin(i->save_extract, fd, temp_path);
}
