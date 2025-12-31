/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <unistd.h>

#include "sd-daemon.h"

#include "build.h"
#include "conf-files.h"
#include "constants.h"
#include "dissect-image.h"
#include "format-table.h"
#include "glyph-util.h"
#include "hexdecoct.h"
#include "image-policy.h"
#include "loop-util.h"
#include "main-func.h"
#include "mount-util.h"
#include "os-util.h"
#include "pager.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "path-util.h"
#include "pretty-print.h"
#include "set.h"
#include "sort-util.h"
#include "specifier.h"
#include "string-util.h"
#include "strv.h"
#include "sysupdate.h"
#include "sysupdate-feature.h"
#include "sysupdate-instance.h"
#include "sysupdate-transfer.h"
#include "sysupdate-update-set.h"
#include "sysupdate-util.h"
#include "utf8.h"
#include "verbs.h"

static char *arg_definitions = NULL;
bool arg_sync = true;
uint64_t arg_instances_max = UINT64_MAX;
static sd_json_format_flags_t arg_json_format_flags = SD_JSON_FORMAT_OFF;
static PagerFlags arg_pager_flags = 0;
static bool arg_legend = true;
char *arg_root = NULL;
static char *arg_image = NULL;
static bool arg_reboot = false;
static char *arg_component = NULL;
static int arg_verify = -1;
static ImagePolicy *arg_image_policy = NULL;
static bool arg_offline = false;
char *arg_transfer_source = NULL;

STATIC_DESTRUCTOR_REGISTER(arg_definitions, freep);
STATIC_DESTRUCTOR_REGISTER(arg_root, freep);
STATIC_DESTRUCTOR_REGISTER(arg_image, freep);
STATIC_DESTRUCTOR_REGISTER(arg_component, freep);
STATIC_DESTRUCTOR_REGISTER(arg_image_policy, image_policy_freep);
STATIC_DESTRUCTOR_REGISTER(arg_transfer_source, freep);

const Specifier specifier_table[] = {
        COMMON_SYSTEM_SPECIFIERS,
        COMMON_TMP_SPECIFIERS,
        {}
};

typedef struct Context {
        Transfer **transfers;
        size_t n_transfers;

        Transfer **disabled_transfers;
        size_t n_disabled_transfers;

        Hashmap *features; /* Defined features, keyed by ID */

        UpdateSet **update_sets;
        size_t n_update_sets;

        UpdateSet *newest_installed, *candidate;

        Hashmap *web_cache; /* Cache for downloaded resources, keyed by URL */
} Context;

static Context* context_free(Context *c) {
        if (!c)
                return NULL;

        FOREACH_ARRAY(tr, c->transfers, c->n_transfers)
                transfer_free(*tr);
        free(c->transfers);

        FOREACH_ARRAY(tr, c->disabled_transfers, c->n_disabled_transfers)
                transfer_free(*tr);
        free(c->disabled_transfers);

        hashmap_free(c->features);

        FOREACH_ARRAY(us, c->update_sets, c->n_update_sets)
                update_set_free(*us);
        free(c->update_sets);

        hashmap_free(c->web_cache);

        return mfree(c);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Context*, context_free);

static Context* context_new(void) {
        /* For now, no fields to initialize non-zero */
        return new0(Context, 1);
}

static void free_transfers(Transfer **array, size_t n) {
        FOREACH_ARRAY(t, array, n)
                transfer_free(*t);
        free(array);
}

static int read_definitions(
                Context *c,
                const char **dirs,
                const char *suffix,
                const char *node) {

        ConfFile **files = NULL;
        Transfer **transfers = NULL, **disabled = NULL;
        size_t n_files = 0, n_transfers = 0, n_disabled = 0;
        int r;

        CLEANUP_ARRAY(files, n_files, conf_file_free_many);
        CLEANUP_ARRAY(transfers, n_transfers, free_transfers);
        CLEANUP_ARRAY(disabled, n_disabled, free_transfers);

        assert(c);
        assert(dirs);
        assert(suffix);

        r = conf_files_list_strv_full(suffix, arg_root,
                                      CONF_FILES_REGULAR|CONF_FILES_FILTER_MASKED|CONF_FILES_WARN,
                                      dirs, &files, &n_files);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate sysupdate.d/*%s definitions: %m", suffix);

        FOREACH_ARRAY(i, files, n_files) {
                _cleanup_(transfer_freep) Transfer *t = NULL;
                Transfer **appended;
                ConfFile *e = *i;

                t = transfer_new(c);
                if (!t)
                        return log_oom();

                r = transfer_read_definition(t, e->result, dirs, c->features);
                if (r < 0)
                        return r;

                r = transfer_resolve_paths(t, arg_root, node);
                if (r < 0)
                        return r;

                if (t->enabled)
                        appended = GREEDY_REALLOC_APPEND(transfers, n_transfers, &t, 1);
                else
                        appended = GREEDY_REALLOC_APPEND(disabled, n_disabled, &t, 1);
                if (!appended)
                        return log_oom();
                TAKE_PTR(t);
        }

        c->transfers = TAKE_PTR(transfers);
        c->n_transfers = n_transfers;
        c->disabled_transfers = TAKE_PTR(disabled);
        c->n_disabled_transfers = n_disabled;
        return 0;
}

static int context_read_definitions(Context *c, const char* node, bool requires_enabled_transfers) {
        _cleanup_strv_free_ char **dirs = NULL;
        int r;

        assert(c);

        if (arg_definitions)
                dirs = strv_new(arg_definitions);
        else if (arg_component) {
                char **l = CONF_PATHS_STRV("");
                size_t i = 0;

                dirs = new0(char*, strv_length(l) + 1);
                if (!dirs)
                        return log_oom();

                STRV_FOREACH(dir, l) {
                        char *j;

                        j = strjoin(*dir, "sysupdate.", arg_component, ".d");
                        if (!j)
                                return log_oom();

                        dirs[i++] = j;
                }
        } else
                dirs = strv_new(CONF_PATHS("sysupdate.d"));
        if (!dirs)
                return log_oom();

        ConfFile **files = NULL;
        size_t n_files = 0;

        CLEANUP_ARRAY(files, n_files, conf_file_free_many);

        r = conf_files_list_strv_full(".feature", arg_root,
                                      CONF_FILES_REGULAR|CONF_FILES_FILTER_MASKED|CONF_FILES_WARN,
                                      (const char**) dirs, &files, &n_files);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate sysupdate.d/*.feature definitions: %m");

        FOREACH_ARRAY(i, files, n_files) {
                _cleanup_(feature_unrefp) Feature *f = NULL;
                ConfFile *e = *i;

                f = feature_new();
                if (!f)
                        return log_oom();

                r = feature_read_definition(f, e->result, (const char**) dirs);
                if (r < 0)
                        return r;

                r = hashmap_ensure_put(&c->features, &feature_hash_ops, f->id, f);
                if (r < 0)
                        return log_error_errno(r, "Failed to insert feature '%s' into map: %m", f->id);
                TAKE_PTR(f);
        }

        r = read_definitions(c, (const char**) dirs, ".transfer", node);
        if (r < 0)
                return r;

        if (c->n_transfers + c->n_disabled_transfers == 0) {
                /* Backwards-compat: If no .transfer defs are found, fall back to trying .conf! */
                r = read_definitions(c, (const char**) dirs, ".conf", node);
                if (r < 0)
                        return r;

                if (c->n_transfers + c->n_disabled_transfers > 0)
                        log_warning("As of v257, transfer definitions should have the '.transfer' extension.");
        }

        if (c->n_transfers + (requires_enabled_transfers ? 0 : c->n_disabled_transfers) == 0) {
                if (arg_component)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOENT),
                                               "No transfer definitions for component '%s' found.",
                                               arg_component);

                return log_error_errno(SYNTHETIC_ERRNO(ENOENT),
                                       "No transfer definitions found.");
        }

        return 0;
}

static int context_load_installed_instances(Context *c) {
        int r;

        assert(c);

        log_info("Discovering installed instances%s", glyph(GLYPH_ELLIPSIS));

        FOREACH_ARRAY(tr, c->transfers, c->n_transfers) {
                Transfer *t = *tr;

                r = resource_load_instances(
                                &t->target,
                                arg_verify >= 0 ? arg_verify : t->verify,
                                &c->web_cache);
                if (r < 0)
                        return r;
        }

        FOREACH_ARRAY(tr, c->disabled_transfers, c->n_disabled_transfers) {
                Transfer *t = *tr;

                r = resource_load_instances(
                                &t->target,
                                arg_verify >= 0 ? arg_verify : t->verify,
                                &c->web_cache);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int context_load_available_instances(Context *c) {
        int r;

        assert(c);

        log_info("Discovering available instances%s", glyph(GLYPH_ELLIPSIS));

        FOREACH_ARRAY(tr, c->transfers, c->n_transfers) {
                Transfer *t = *tr;

                r = resource_load_instances(
                                &t->source,
                                arg_verify >= 0 ? arg_verify : t->verify,
                                &c->web_cache);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int context_discover_update_sets_by_flag(Context *c, UpdateSetFlags flags) {
        _cleanup_free_ char *boundary = NULL;
        bool newest_found = false;
        int r;

        assert(c);
        assert(IN_SET(flags, UPDATE_AVAILABLE, UPDATE_INSTALLED));

        for (;;) {
                _cleanup_free_ Instance **cursor_instances = NULL;
                bool skip = false;
                UpdateSetFlags extra_flags = 0;
                _cleanup_free_ char *cursor = NULL;
                UpdateSet *us = NULL;

                /* First, let's find the newest version that's older than the boundary. */
                FOREACH_ARRAY(tr, c->transfers, c->n_transfers) {
                        Resource *rr;

                        assert(*tr);

                        if (flags == UPDATE_AVAILABLE)
                                rr = &(*tr)->source;
                        else {
                                assert(flags == UPDATE_INSTALLED);
                                rr = &(*tr)->target;
                        }

                        FOREACH_ARRAY(inst, rr->instances, rr->n_instances) {
                                Instance *i = *inst; /* Sorted newest-to-oldest */

                                assert(i);

                                if (boundary && strverscmp_improved(i->metadata.version, boundary) >= 0)
                                        continue; /* Not older than the boundary */

                                if (cursor && strverscmp(i->metadata.version, cursor) <= 0)
                                        break; /* Not newer than the cursor. The same will be true for all
                                                * subsequent instances (due to sorting) so let's skip to the
                                                * next transfer. */

                                if (free_and_strdup(&cursor, i->metadata.version) < 0)
                                        return log_oom();

                                break; /* All subsequent instances will be older than this one */
                        }

                        if (flags == UPDATE_AVAILABLE && !cursor)
                                break; /* This transfer didn't have a version older than the boundary,
                                        * so any older-than-boundary version that might exist in a different
                                        * transfer must always be incomplete. For reasons described below,
                                        * we don't include incomplete versions for AVAILABLE updates. So we
                                        * are completely done looking. */
                }

                if (!cursor) /* We didn't find anything older than the boundary, so we're done. */
                        break;

                cursor_instances = new0(Instance*, c->n_transfers);
                if (!cursor_instances)
                        return log_oom();

                /* Now let's find all the instances that match the version of the cursor, if we have them */
                for (size_t k = 0; k < c->n_transfers; k++) {
                        Transfer *t = c->transfers[k];
                        Instance *match = NULL;

                        assert(t);

                        if (flags == UPDATE_AVAILABLE) {
                                match = resource_find_instance(&t->source, cursor);
                                if (!match) {
                                        /* When we're looking for updates to download, we don't offer
                                         * incomplete versions at all. The server wants to send us an update
                                         * with parts of the OS missing. For robustness sake, let's not do
                                         * that. */
                                        skip = true;
                                        break;
                                }
                        } else {
                                assert(flags == UPDATE_INSTALLED);

                                match = resource_find_instance(&t->target, cursor);
                                if (!match && !(extra_flags & (UPDATE_PARTIAL|UPDATE_PENDING))) {
                                        /* When we're looking for installed versions, let's be robust and treat
                                         * an incomplete installation as an installation. Otherwise, there are
                                         * situations that can lead to sysupdate wiping the currently booted OS.
                                         * See https://github.com/systemd/systemd/issues/33339 */
                                        extra_flags |= UPDATE_INCOMPLETE;
                                }
                        }

                        cursor_instances[k] = match;

                        if (t->min_version && strverscmp_improved(t->min_version, cursor) > 0)
                                extra_flags |= UPDATE_OBSOLETE;

                        if (strv_contains(t->protected_versions, cursor))
                                extra_flags |= UPDATE_PROTECTED;

                        /* Partial or pending updates by definition are not incomplete, they’re
                         * partial/pending instead */
                        if (match && match->is_partial)
                                extra_flags = (extra_flags | UPDATE_PARTIAL) & ~UPDATE_INCOMPLETE;

                        if (match && match->is_pending)
                                extra_flags = (extra_flags | UPDATE_PENDING) & ~UPDATE_INCOMPLETE;
                }

                r = free_and_strdup_warn(&boundary, cursor);
                if (r < 0)
                        return r;

                if (skip)
                        continue;

                /* See if we already have this update set in our table */
                FOREACH_ARRAY(update_set, c->update_sets, c->n_update_sets) {
                        UpdateSet *u = *update_set;

                        if (strverscmp_improved(u->version, cursor) != 0)
                                continue;

                        /* Merge in what we've learned and continue onto the next version */

                        if (FLAGS_SET(u->flags, UPDATE_INCOMPLETE) ||
                            FLAGS_SET(u->flags, UPDATE_PARTIAL) ||
                            FLAGS_SET(u->flags, UPDATE_PENDING)) {
                                assert(u->n_instances == c->n_transfers);

                                /* Incomplete updates will have picked NULL instances for the transfers that
                                 * are missing. Now we have more information, so let's try to fill them in. */

                                for (size_t j = 0; j < u->n_instances; j++) {
                                        if (!u->instances[j])
                                                u->instances[j] = cursor_instances[j];

                                        /* Make sure that the list is full if the update is AVAILABLE */
                                        assert(flags != UPDATE_AVAILABLE || u->instances[j]);
                                }
                        }

                        u->flags |= flags | extra_flags;

                        /* If this is the newest installed version, that is incomplete and just became marked
                         * as available, and if there is no other candidate available, we promote this to be
                         * the candidate. Ignore partial or pending status on the update set. */
                        if (FLAGS_SET(u->flags, UPDATE_NEWEST|UPDATE_INSTALLED|UPDATE_INCOMPLETE|UPDATE_AVAILABLE) &&
                            !c->candidate && !FLAGS_SET(u->flags, UPDATE_OBSOLETE))
                                c->candidate = u;

                        skip = true;
                        newest_found = true;
                        break;
                }

                if (skip)
                        continue;

                /* Doesn't exist yet, let's add it */
                if (!GREEDY_REALLOC(c->update_sets, c->n_update_sets + 1))
                        return log_oom();

                us = new(UpdateSet, 1);
                if (!us)
                        return log_oom();

                *us = (UpdateSet) {
                        .flags = flags | (newest_found ? 0 : UPDATE_NEWEST) | extra_flags,
                        .version = TAKE_PTR(cursor),
                        .instances = TAKE_PTR(cursor_instances),
                        .n_instances = c->n_transfers,
                };

                c->update_sets[c->n_update_sets++] = us;

                newest_found = true;

                /* Remember which one is the newest installed */
                if ((us->flags & (UPDATE_NEWEST|UPDATE_INSTALLED)) == (UPDATE_NEWEST|UPDATE_INSTALLED))
                        c->newest_installed = us;

                /* Remember which is the newest non-obsolete, available (and not installed) version, which we declare the "candidate".
                 * It may be partial or pending. */
                if ((us->flags & (UPDATE_NEWEST|UPDATE_INSTALLED|UPDATE_AVAILABLE|UPDATE_OBSOLETE)) == (UPDATE_NEWEST|UPDATE_AVAILABLE))
                        c->candidate = us;
        }

        /* Newest installed is newer than or equal to candidate? Then suppress the candidate */
        if (c->newest_installed && !FLAGS_SET(c->newest_installed->flags, UPDATE_INCOMPLETE) &&
            c->candidate && strverscmp_improved(c->newest_installed->version, c->candidate->version) >= 0)
                c->candidate = NULL;

        /* Newest installed is still pending and no candidate is set? Then it becomes the candidate. */
        if (c->newest_installed && FLAGS_SET(c->newest_installed->flags, UPDATE_PENDING) &&
            !c->candidate)
                c->candidate = c->newest_installed;

        return 0;
}

static int context_discover_update_sets(Context *c) {
        int r;

        assert(c);

        log_info("Determining installed update sets%s", glyph(GLYPH_ELLIPSIS));

        r = context_discover_update_sets_by_flag(c, UPDATE_INSTALLED);
        if (r < 0)
                return r;

        if (!arg_offline) {
                log_info("Determining available update sets%s", glyph(GLYPH_ELLIPSIS));

                r = context_discover_update_sets_by_flag(c, UPDATE_AVAILABLE);
                if (r < 0)
                        return r;
        }

        typesafe_qsort(c->update_sets, c->n_update_sets, update_set_cmp);
        return 0;
}

static int context_show_table(Context *c) {
        _cleanup_(table_unrefp) Table *t = NULL;
        int r;

        assert(c);

        t = table_new("", "version", "installed", "available", "assessment");
        if (!t)
                return log_oom();

        (void) table_set_align_percent(t, table_get_cell(t, 0, 0), 100);
        (void) table_set_align_percent(t, table_get_cell(t, 0, 2), 50);
        (void) table_set_align_percent(t, table_get_cell(t, 0, 3), 50);

        FOREACH_ARRAY(update_set, c->update_sets, c->n_update_sets) {
                UpdateSet *us = *update_set;
                const char *color;

                color = update_set_flags_to_color(us->flags);

                r = table_add_many(t,
                                   TABLE_STRING,    update_set_flags_to_glyph(us->flags),
                                   TABLE_SET_COLOR, color,
                                   TABLE_STRING,    us->version,
                                   TABLE_SET_COLOR, color,
                                   TABLE_STRING,    glyph_check_mark_space(FLAGS_SET(us->flags, UPDATE_INSTALLED)),
                                   TABLE_SET_COLOR, color,
                                   TABLE_STRING,    glyph_check_mark_space(FLAGS_SET(us->flags, UPDATE_AVAILABLE)),
                                   TABLE_SET_COLOR, color,
                                   TABLE_STRING,    update_set_flags_to_string(us->flags),
                                   TABLE_SET_COLOR, color);
                if (r < 0)
                        return table_log_add_error(r);
        }

        return table_print_with_pager(t, arg_json_format_flags, arg_pager_flags, arg_legend);
}

static UpdateSet* context_update_set_by_version(Context *c, const char *version) {
        assert(c);
        assert(version);

        FOREACH_ARRAY(update_set, c->update_sets, c->n_update_sets)
                if (streq((*update_set)->version, version))
                        return *update_set;

        return NULL;
}

static int context_show_version(Context *c, const char *version) {
        bool show_fs_columns = false, show_partition_columns = false,
                have_fs_attributes = false, have_partition_attributes = false,
                have_size = false, have_tries = false, have_no_auto = false,
                have_read_only = false, have_growfs = false, have_sha256 = false;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *json = NULL;
        _cleanup_(table_unrefp) Table *t = NULL;
        _cleanup_strv_free_ char **changelog_urls = NULL;
        UpdateSet *us;
        int r;

        assert(c);
        assert(version);

        us = context_update_set_by_version(c, version);
        if (!us)
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "Update '%s' not found.", version);

        if (arg_json_format_flags & (SD_JSON_FORMAT_OFF|SD_JSON_FORMAT_PRETTY|SD_JSON_FORMAT_PRETTY_AUTO))
                pager_open(arg_pager_flags);

        if (!sd_json_format_enabled(arg_json_format_flags))
                printf("%s%s%s Version: %s\n"
                       "    State: %s%s%s\n"
                       "Installed: %s%s%s%s\n"
                       "Available: %s%s\n"
                       "Protected: %s%s%s\n"
                       " Obsolete: %s%s%s\n\n",
                       strempty(update_set_flags_to_color(us->flags)), update_set_flags_to_glyph(us->flags), ansi_normal(), us->version,
                       strempty(update_set_flags_to_color(us->flags)), update_set_flags_to_string(us->flags), ansi_normal(),
                       yes_no(us->flags & UPDATE_INSTALLED), FLAGS_SET(us->flags, UPDATE_INSTALLED|UPDATE_NEWEST) ? " (newest)" : "",
                       FLAGS_SET(us->flags, UPDATE_INSTALLED|UPDATE_PENDING) ? " (pending)" : "", FLAGS_SET(us->flags, UPDATE_INSTALLED|UPDATE_PARTIAL) ? " (partial)" : "",
                       yes_no(us->flags & UPDATE_AVAILABLE), (us->flags & (UPDATE_INSTALLED|UPDATE_AVAILABLE|UPDATE_NEWEST)) == (UPDATE_AVAILABLE|UPDATE_NEWEST) ? " (newest)" : "",
                       FLAGS_SET(us->flags, UPDATE_INSTALLED|UPDATE_PROTECTED) ? ansi_highlight() : "", yes_no(FLAGS_SET(us->flags, UPDATE_INSTALLED|UPDATE_PROTECTED)), ansi_normal(),
                       us->flags & UPDATE_OBSOLETE ? ansi_highlight_red() : "", yes_no(us->flags & UPDATE_OBSOLETE), ansi_normal());

        t = table_new("type", "path", "ptuuid", "ptflags", "mtime", "mode", "size", "tries-done", "tries-left", "noauto", "ro", "growfs", "sha256");
        if (!t)
                return log_oom();

        (void) table_set_align_percent(t, table_get_cell(t, 0, 3), 100);
        (void) table_set_align_percent(t, table_get_cell(t, 0, 4), 100);
        (void) table_set_align_percent(t, table_get_cell(t, 0, 5), 100);
        (void) table_set_align_percent(t, table_get_cell(t, 0, 6), 100);
        (void) table_set_align_percent(t, table_get_cell(t, 0, 7), 100);
        (void) table_set_align_percent(t, table_get_cell(t, 0, 8), 100);
        table_set_ersatz_string(t, TABLE_ERSATZ_DASH);

        /* Starting in v257, these fields would be automatically formatted with underscores. This would have
         * been a breaking change, so to avoid that let's hard-code their original names. */
        (void) table_set_json_field_name(t, 7, "tries-done");
        (void) table_set_json_field_name(t, 8, "tries-left");

        /* Determine if the target will make use of partition/fs attributes for any of the transfers */
        FOREACH_ARRAY(transfer, c->transfers, c->n_transfers) {
                Transfer *tr = *transfer;

                if (tr->target.type == RESOURCE_PARTITION)
                        show_partition_columns = true;
                if (RESOURCE_IS_FILESYSTEM(tr->target.type))
                        show_fs_columns = true;

                STRV_FOREACH(changelog, tr->changelog) {
                        assert(*changelog);

                        _cleanup_free_ char *changelog_url = strreplace(*changelog, "@v", version);
                        if (!changelog_url)
                                return log_oom();

                        /* Avoid duplicates */
                        if (strv_contains(changelog_urls, changelog_url))
                                continue;

                        /* changelog_urls takes ownership of expanded changelog_url */
                        r = strv_consume(&changelog_urls, TAKE_PTR(changelog_url));
                        if (r < 0)
                                return log_oom();
                }
        }

        FOREACH_ARRAY(inst, us->instances, us->n_instances) {
                Instance *i = *inst;

                if (!i) {
                        assert(FLAGS_SET(us->flags, UPDATE_INCOMPLETE));
                        continue;
                }

                r = table_add_many(t,
                                   TABLE_STRING, resource_type_to_string(i->resource->type),
                                   TABLE_PATH, i->path);
                if (r < 0)
                        return table_log_add_error(r);

                if (i->metadata.partition_uuid_set) {
                        have_partition_attributes = true;
                        r = table_add_cell(t, NULL, TABLE_UUID, &i->metadata.partition_uuid);
                } else
                        r = table_add_cell(t, NULL, TABLE_EMPTY, NULL);
                if (r < 0)
                        return table_log_add_error(r);

                if (i->metadata.partition_flags_set) {
                        have_partition_attributes = true;
                        r = table_add_cell(t, NULL, TABLE_UINT64_HEX, &i->metadata.partition_flags);
                } else
                        r = table_add_cell(t, NULL, TABLE_EMPTY, NULL);
                if (r < 0)
                        return table_log_add_error(r);

                if (i->metadata.mtime != USEC_INFINITY) {
                        have_fs_attributes = true;
                        r = table_add_cell(t, NULL, TABLE_TIMESTAMP, &i->metadata.mtime);
                } else
                        r = table_add_cell(t, NULL, TABLE_EMPTY, NULL);
                if (r < 0)
                        return table_log_add_error(r);

                if (i->metadata.mode != MODE_INVALID) {
                        have_fs_attributes = true;
                        r = table_add_cell(t, NULL, TABLE_MODE, &i->metadata.mode);
                } else
                        r = table_add_cell(t, NULL, TABLE_EMPTY, NULL);
                if (r < 0)
                        return table_log_add_error(r);

                if (i->metadata.size != UINT64_MAX) {
                        have_size = true;
                        r = table_add_cell(t, NULL, TABLE_SIZE, &i->metadata.size);
                } else
                        r = table_add_cell(t, NULL, TABLE_EMPTY, NULL);
                if (r < 0)
                        return table_log_add_error(r);

                if (i->metadata.tries_done != UINT64_MAX) {
                        have_tries = true;
                        r = table_add_cell(t, NULL, TABLE_UINT64, &i->metadata.tries_done);
                } else
                        r = table_add_cell(t, NULL, TABLE_EMPTY, NULL);
                if (r < 0)
                        return table_log_add_error(r);

                if (i->metadata.tries_left != UINT64_MAX) {
                        have_tries = true;
                        r = table_add_cell(t, NULL, TABLE_UINT64, &i->metadata.tries_left);
                } else
                        r = table_add_cell(t, NULL, TABLE_EMPTY, NULL);
                if (r < 0)
                        return table_log_add_error(r);

                if (i->metadata.no_auto >= 0) {
                        bool b;

                        have_no_auto = true;
                        b = i->metadata.no_auto;
                        r = table_add_cell(t, NULL, TABLE_BOOLEAN, &b);
                } else
                        r = table_add_cell(t, NULL, TABLE_EMPTY, NULL);
                if (r < 0)
                        return table_log_add_error(r);
                if (i->metadata.read_only >= 0) {
                        bool b;

                        have_read_only = true;
                        b = i->metadata.read_only;
                        r = table_add_cell(t, NULL, TABLE_BOOLEAN, &b);
                } else
                        r = table_add_cell(t, NULL, TABLE_EMPTY, NULL);
                if (r < 0)
                        return table_log_add_error(r);

                if (i->metadata.growfs >= 0) {
                        bool b;

                        have_growfs = true;
                        b = i->metadata.growfs;
                        r = table_add_cell(t, NULL, TABLE_BOOLEAN, &b);
                } else
                        r = table_add_cell(t, NULL, TABLE_EMPTY, NULL);
                if (r < 0)
                        return table_log_add_error(r);

                if (i->metadata.sha256sum_set) {
                        _cleanup_free_ char *formatted = NULL;

                        have_sha256 = true;

                        formatted = hexmem(i->metadata.sha256sum, sizeof(i->metadata.sha256sum));
                        if (!formatted)
                                return log_oom();

                        r = table_add_cell(t, NULL, TABLE_STRING, formatted);
                } else
                        r = table_add_cell(t, NULL, TABLE_EMPTY, NULL);
                if (r < 0)
                        return table_log_add_error(r);
        }

        /* Hide the fs/partition columns if we don't have any data to show there */
        if (!have_fs_attributes)
                show_fs_columns = false;
        if (!have_partition_attributes)
                show_partition_columns = false;

        if (!show_partition_columns)
                (void) table_hide_column_from_display(t, 2, 3);
        if (!show_fs_columns)
                (void) table_hide_column_from_display(t, 4, 5);
        if (!have_size)
                (void) table_hide_column_from_display(t, 6);
        if (!have_tries)
                (void) table_hide_column_from_display(t, 7, 8);
        if (!have_no_auto)
                (void) table_hide_column_from_display(t, 9);
        if (!have_read_only)
                (void) table_hide_column_from_display(t, 10);
        if (!have_growfs)
                (void) table_hide_column_from_display(t, 11);
        if (!have_sha256)
                (void) table_hide_column_from_display(t, 12);

        if (!sd_json_format_enabled(arg_json_format_flags)) {
                printf("%s%s%s Version: %s\n"
                       "    State: %s%s%s\n"
                       "Installed: %s%s%s%s%s%s%s\n"
                       "Available: %s%s\n"
                       "Protected: %s%s%s\n"
                       " Obsolete: %s%s%s\n",
                       strempty(update_set_flags_to_color(us->flags)), update_set_flags_to_glyph(us->flags), ansi_normal(), us->version,
                       strempty(update_set_flags_to_color(us->flags)), update_set_flags_to_string(us->flags), ansi_normal(),
                       yes_no(us->flags & UPDATE_INSTALLED), FLAGS_SET(us->flags, UPDATE_INSTALLED|UPDATE_NEWEST) ? " (newest)" : "",
                       FLAGS_SET(us->flags, UPDATE_INCOMPLETE) ? ansi_highlight_yellow() : "", FLAGS_SET(us->flags, UPDATE_INCOMPLETE) ? " (incomplete)" : "", ansi_normal(),
                       FLAGS_SET(us->flags, UPDATE_INSTALLED|UPDATE_PENDING) ? " (pending)" : "", FLAGS_SET(us->flags, UPDATE_INSTALLED|UPDATE_PARTIAL) ? " (partial)" : "",
                       yes_no(us->flags & UPDATE_AVAILABLE), (us->flags & (UPDATE_INSTALLED|UPDATE_AVAILABLE|UPDATE_NEWEST)) == (UPDATE_AVAILABLE|UPDATE_NEWEST) ? " (newest)" : "",
                       FLAGS_SET(us->flags, UPDATE_INSTALLED|UPDATE_PROTECTED) ? ansi_highlight() : "", yes_no(FLAGS_SET(us->flags, UPDATE_INSTALLED|UPDATE_PROTECTED)), ansi_normal(),
                       us->flags & UPDATE_OBSOLETE ? ansi_highlight_red() : "", yes_no(us->flags & UPDATE_OBSOLETE), ansi_normal());

                STRV_FOREACH(url, changelog_urls) {
                        _cleanup_free_ char *changelog_link = NULL;
                        r = terminal_urlify(*url, NULL, &changelog_link);
                        if (r < 0)
                                return log_oom();
                        printf("ChangeLog: %s\n", changelog_link);
                }
                printf("\n");

                return table_print_with_pager(t, arg_json_format_flags, arg_pager_flags, arg_legend);
        } else {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *t_json = NULL;

                r = table_to_json(t, &t_json);
                if (r < 0)
                        return log_error_errno(r, "failed to convert table to JSON: %m");

                r = sd_json_buildo(&json, SD_JSON_BUILD_PAIR_STRING("version", us->version),
                                          SD_JSON_BUILD_PAIR_BOOLEAN("newest", FLAGS_SET(us->flags, UPDATE_NEWEST)),
                                          SD_JSON_BUILD_PAIR_BOOLEAN("available", FLAGS_SET(us->flags, UPDATE_AVAILABLE)),
                                          SD_JSON_BUILD_PAIR_BOOLEAN("installed", FLAGS_SET(us->flags, UPDATE_INSTALLED)),
                                          SD_JSON_BUILD_PAIR_BOOLEAN("partial", FLAGS_SET(us->flags, UPDATE_PARTIAL)),
                                          SD_JSON_BUILD_PAIR_BOOLEAN("pending", FLAGS_SET(us->flags, UPDATE_PENDING)),
                                          SD_JSON_BUILD_PAIR_BOOLEAN("obsolete", FLAGS_SET(us->flags, UPDATE_OBSOLETE)),
                                          SD_JSON_BUILD_PAIR_BOOLEAN("protected", FLAGS_SET(us->flags, UPDATE_PROTECTED)),
                                          SD_JSON_BUILD_PAIR_BOOLEAN("incomplete", FLAGS_SET(us->flags, UPDATE_INCOMPLETE)),
                                          SD_JSON_BUILD_PAIR_STRV("changelogUrls", changelog_urls),
                                          SD_JSON_BUILD_PAIR_VARIANT("contents", t_json));
                if (r < 0)
                        return log_error_errno(r, "Failed to create JSON: %m");

                r = sd_json_variant_dump(json, arg_json_format_flags, stdout, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to print JSON: %m");

                return 0;
        }
}

static int context_vacuum(
                Context *c,
                uint64_t space,
                const char *extra_protected_version) {

        size_t disabled_count = 0;
        int r, count = 0;

        assert(c);

        if (space == 0)
                log_info("Making room%s", glyph(GLYPH_ELLIPSIS));
        else
                log_info("Making room for %" PRIu64 " updates%s", space, glyph(GLYPH_ELLIPSIS));

        FOREACH_ARRAY(tr, c->transfers, c->n_transfers) {
                Transfer *t = *tr;

                /* Don't bother clearing out space if we're not going to be downloading anything */
                if (extra_protected_version && resource_find_instance(&t->target, extra_protected_version))
                        continue;

                r = transfer_vacuum(t, space, extra_protected_version);
                if (r < 0)
                        return r;

                count = MAX(count, r);
        }

        FOREACH_ARRAY(tr, c->disabled_transfers, c->n_disabled_transfers) {
                r = transfer_vacuum(*tr, UINT64_MAX /* wipe all instances */, NULL);
                if (r < 0)
                        return r;
                if (r > 0)
                        disabled_count++;
        }

        if (!sd_json_format_enabled(arg_json_format_flags)) {
                if (count > 0 && disabled_count > 0)
                        log_info("Removed %i instances, and %zu disabled transfers.", count, disabled_count);
                else if (count > 0)
                        log_info("Removed %i instances.", count);
                else if (disabled_count > 0)
                        log_info("Removed %zu disabled transfers.", disabled_count);
                else
                        log_info("Found nothing to remove.");
        } else {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *json = NULL;

                r = sd_json_buildo(&json,
                                   SD_JSON_BUILD_PAIR_INTEGER("removed", count),
                                   SD_JSON_BUILD_PAIR_UNSIGNED("disabledTransfers", disabled_count));
                if (r < 0)
                        return log_error_errno(r, "Failed to create JSON: %m");

                r = sd_json_variant_dump(json, arg_json_format_flags, stdout, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to print JSON: %m");
        }

        return 0;
}

static int context_make_offline(Context **ret, const char *node, bool requires_enabled_transfers) {
        _cleanup_(context_freep) Context* context = NULL;
        int r;

        assert(ret);

        /* Allocates a context object and initializes everything we can initialize offline, i.e. without
         * checking on the update source (i.e. the Internet) what versions are available */

        context = context_new();
        if (!context)
                return log_oom();

        r = context_read_definitions(context, node, requires_enabled_transfers);
        if (r < 0)
                return r;

        r = context_load_installed_instances(context);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(context);
        return 0;
}

static int context_make_online(Context **ret, const char *node) {
        _cleanup_(context_freep) Context* context = NULL;
        int r;

        assert(ret);

        /* Like context_make_offline(), but also communicates with the update source looking for new
         * versions (as long as --offline is not specified on the command line). */

        r = context_make_offline(&context, node, /* requires_enabled_transfers= */ true);
        if (r < 0)
                return r;

        if (!arg_offline) {
                r = context_load_available_instances(context);
                if (r < 0)
                        return r;
        }

        r = context_discover_update_sets(context);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(context);
        return 0;
}

static int context_on_acquire_progress(const Transfer *t, const Instance *inst, unsigned percentage) {
        const Context *c = ASSERT_PTR(t->context);
        size_t i, n = c->n_transfers;
        uint64_t base, scaled;
        unsigned overall;

        for (i = 0; i < n; i++)
                if (c->transfers[i] == t)
                        break;
        assert(i < n); /* We should have found the index */

        base = (100 * 100 * i) / n;
        scaled = (100 * percentage) / n;
        overall = (unsigned) ((base + scaled) / 100);
        assert(overall <= 100);

        log_debug("Transfer %zu/%zu is %u%% complete (%u%% overall).", i+1, n, percentage, overall);
        return sd_notifyf(/* unset_environment= */ false, "X_SYSUPDATE_PROGRESS=%u\n"
                                              "X_SYSUPDATE_TRANSFERS_LEFT=%zu\n"
                                              "X_SYSUPDATE_TRANSFERS_DONE=%zu\n"
                                              "STATUS=Updating to '%s' (%u%% complete).",
                                              overall, n - i, i, inst->metadata.version, overall);
}

static int context_process_partial_and_pending(Context *c, const char *version);

static int context_acquire(
                Context *c,
                const char *version) {

        UpdateSet *us = NULL;
        int r;

        assert(c);

        if (version) {
                us = context_update_set_by_version(c, version);
                if (!us)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "Update '%s' not found.", version);
        } else {
                if (!c->candidate) {
                        log_info("No update needed.");

                        return 0;
                }

                us = c->candidate;
        }

        if (FLAGS_SET(us->flags, UPDATE_INCOMPLETE))
                log_info("Selected update '%s' is already installed, but incomplete. Repairing.", us->version);
        else if (FLAGS_SET(us->flags, UPDATE_PARTIAL)) {
                log_info("Selected update '%s' is already acquired and partially installed. Vacuum it to try installing again.", us->version);

                return 0;
        } else if (FLAGS_SET(us->flags, UPDATE_PENDING)) {
                log_info("Selected update '%s' is already acquired and pending installation.", us->version);

                return context_process_partial_and_pending(c, version);
        } else if (FLAGS_SET(us->flags, UPDATE_INSTALLED)) {
                log_info("Selected update '%s' is already installed. Skipping update.", us->version);

                return 0;
        }

        if (!FLAGS_SET(us->flags, UPDATE_AVAILABLE))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Selected update '%s' is not available, refusing.", us->version);
        if (FLAGS_SET(us->flags, UPDATE_OBSOLETE))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Selected update '%s' is obsolete, refusing.", us->version);

        if (!FLAGS_SET(us->flags, UPDATE_NEWEST))
                log_notice("Selected update '%s' is not the newest, proceeding anyway.", us->version);
        if (c->newest_installed && strverscmp_improved(c->newest_installed->version, us->version) > 0)
                log_notice("Selected update '%s' is older than newest installed version, proceeding anyway.", us->version);

        log_info("Selected update '%s' for install.", us->version);

        (void) sd_notifyf(/* unset_environment= */ false,
                          "READY=1\n"
                          "X_SYSUPDATE_VERSION=%s\n"
                          "STATUS=Making room for '%s'.", us->version, us->version);

        /* Let's make some room. We make sure for each transfer we have one free space to fill. While
         * removing stuff we'll protect the version we are trying to acquire. Why that? Maybe an earlier
         * download succeeded already, in which case we shouldn't remove it just to acquire it again */
        r = context_vacuum(
                        c,
                        /* space= */ 1,
                        /* extra_protected_version= */ us->version);
        if (r < 0)
                return r;

        if (arg_sync)
                sync();

        (void) sd_notifyf(/* unset_environment= */ false,
                          "STATUS=Updating to '%s'.", us->version);

        /* There should now be one instance picked for each transfer, and the order is the same */
        assert(us->n_instances == c->n_transfers);

        for (size_t i = 0; i < c->n_transfers; i++) {
                Instance *inst = us->instances[i];
                Transfer *t = c->transfers[i];

                assert(inst); /* ditto */

                if (inst->resource == &t->target) { /* a present transfer in an incomplete installation */
                        assert(FLAGS_SET(us->flags, UPDATE_INCOMPLETE));
                        continue;
                }

                r = transfer_acquire_instance(t, inst, context_on_acquire_progress, c);
                if (r < 0)
                        return r;
        }

        if (arg_sync)
                sync();

        return 1;
}

/* Check to see if we have an update set acquired and pending installation. */
static int context_process_partial_and_pending(
                Context *c,
                const char *version) {

        UpdateSet *us = NULL;
        int r;

        assert(c);

        if (version) {
                us = context_update_set_by_version(c, version);
                if (!us)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "Update '%s' not found.", version);
        } else {
                if (!c->candidate) {
                        log_info("No update needed.");

                        return 0;
                }

                us = c->candidate;
        }

        if (FLAGS_SET(us->flags, UPDATE_INCOMPLETE))
                log_info("Selected update '%s' is already installed, but incomplete. Repairing.", us->version);
        else if ((us->flags & (UPDATE_PARTIAL|UPDATE_PENDING|UPDATE_INSTALLED)) == UPDATE_INSTALLED) {
                log_info("Selected update '%s' is already installed. Skipping update.", us->version);

                return 0;
        }

        if (FLAGS_SET(us->flags, UPDATE_PARTIAL))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Selected update '%s' is only partially downloaded, refusing.", us->version);
        if (!FLAGS_SET(us->flags, UPDATE_PENDING))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Selected update '%s' is not pending installation, refusing.", us->version);

        if (FLAGS_SET(us->flags, UPDATE_OBSOLETE))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Selected update '%s' is obsolete, refusing.", us->version);

        if (!FLAGS_SET(us->flags, UPDATE_NEWEST))
                log_notice("Selected update '%s' is not the newest, proceeding anyway.", us->version);
        if (c->newest_installed && strverscmp_improved(c->newest_installed->version, us->version) > 0)
                log_notice("Selected update '%s' is older than newest installed version, proceeding anyway.", us->version);

        log_info("Selected update '%s' for install.", us->version);

        /* There should now be one instance picked for each transfer, and the order is the same */
        assert(us->n_instances == c->n_transfers);

        for (size_t i = 0; i < c->n_transfers; i++) {
                Instance *inst = us->instances[i];
                Transfer *t = c->transfers[i];

                assert(inst);

                r = transfer_process_partial_and_pending_instance(t, inst);
                if (r < 0)
                        return r;
        }

        return 1;
}

static int context_install(
                Context *c,
                const char *version,
                UpdateSet **ret_applied) {

        UpdateSet *us = NULL;
        int r;

        assert(c);

        if (version) {
                us = context_update_set_by_version(c, version);
                if (!us)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "Update '%s' not found.", version);
        } else {
                if (!c->candidate) {
                        log_info("No update needed.");

                        return 0;
                }

                us = c->candidate;
        }

        (void) sd_notifyf(/* unset_environment=*/ false,
                          "STATUS=Installing '%s'.", us->version);

        for (size_t i = 0; i < c->n_transfers; i++) {
                Instance *inst = us->instances[i];
                Transfer *t = c->transfers[i];

                if (inst->resource == &t->target &&
                    !inst->is_pending)
                        continue;

                r = transfer_install_instance(t, inst, arg_root);
                if (r < 0)
                        return r;
        }

        log_info("%s Successfully installed update '%s'.", glyph(GLYPH_SPARKLES), us->version);

        (void) sd_notifyf(/* unset_environment= */ false,
                          "STATUS=Installed '%s'.", us->version);

        if (ret_applied)
                *ret_applied = us;

        return 1;
}

static int process_image(
                bool ro,
                char **ret_mounted_dir,
                LoopDevice **ret_loop_device) {

        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(umount_and_freep) char *mounted_dir = NULL;
        int r;

        assert(ret_mounted_dir);
        assert(ret_loop_device);

        if (!arg_image)
                return 0;

        assert(!arg_root);

        r = mount_image_privately_interactively(
                        arg_image,
                        arg_image_policy,
                        (ro ? DISSECT_IMAGE_READ_ONLY : 0) |
                        DISSECT_IMAGE_FSCK |
                        DISSECT_IMAGE_MKDIR |
                        DISSECT_IMAGE_GROWFS |
                        DISSECT_IMAGE_RELAX_VAR_CHECK |
                        DISSECT_IMAGE_USR_NO_ROOT |
                        DISSECT_IMAGE_GENERIC_ROOT |
                        DISSECT_IMAGE_REQUIRE_ROOT |
                        DISSECT_IMAGE_ALLOW_USERSPACE_VERITY,
                        &mounted_dir,
                        /* ret_dir_fd= */ NULL,
                        &loop_device);
        if (r < 0)
                return r;

        arg_root = strdup(mounted_dir);
        if (!arg_root)
                return log_oom();

        *ret_mounted_dir = TAKE_PTR(mounted_dir);
        *ret_loop_device = TAKE_PTR(loop_device);

        return 0;
}

static int verb_list(int argc, char **argv, void *userdata) {
        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(umount_and_rmdir_and_freep) char *mounted_dir = NULL;
        _cleanup_(context_freep) Context* context = NULL;
        _cleanup_strv_free_ char **appstream_urls = NULL;
        const char *version;
        int r;

        assert(argc <= 2);
        version = argc >= 2 ? argv[1] : NULL;

        r = process_image(/* ro= */ true, &mounted_dir, &loop_device);
        if (r < 0)
                return r;

        r = context_make_online(&context, loop_device ? loop_device->node : NULL);
        if (r < 0)
                return r;

        if (version)
                return context_show_version(context, version);
        else if (!sd_json_format_enabled(arg_json_format_flags))
                return context_show_table(context);
        else {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *json = NULL;
                _cleanup_strv_free_ char **versions = NULL;
                const char *current = NULL;
                bool current_is_pending = false;

                FOREACH_ARRAY(update_set, context->update_sets, context->n_update_sets) {
                        UpdateSet *us = *update_set;

                        if (FLAGS_SET(us->flags, UPDATE_INSTALLED) &&
                            FLAGS_SET(us->flags, UPDATE_NEWEST)) {
                                current = us->version;
                                current_is_pending = FLAGS_SET(us->flags, UPDATE_PENDING);
                        }

                        r = strv_extend(&versions, us->version);
                        if (r < 0)
                                return log_oom();
                }

                FOREACH_ARRAY(tr, context->transfers, context->n_transfers)
                        STRV_FOREACH(appstream_url, (*tr)->appstream) {
                                /* Avoid duplicates */
                                if (strv_contains(appstream_urls, *appstream_url))
                                        continue;

                                r = strv_extend(&appstream_urls, *appstream_url);
                                if (r < 0)
                                        return log_oom();
                        }

                r = sd_json_buildo(&json, SD_JSON_BUILD_PAIR_STRING(current_is_pending ? "current+pending" : "current", current),
                                          SD_JSON_BUILD_PAIR_STRV("all", versions),
                                          SD_JSON_BUILD_PAIR_STRV("appstreamUrls", appstream_urls));
                if (r < 0)
                        return log_error_errno(r, "Failed to create JSON: %m");

                r = sd_json_variant_dump(json, arg_json_format_flags, stdout, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to print JSON: %m");

                return 0;
        }
}

static int verb_features(int argc, char **argv, void *userdata) {
        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(umount_and_rmdir_and_freep) char *mounted_dir = NULL;
        _cleanup_(context_freep) Context* context = NULL;
        _cleanup_(table_unrefp) Table *table = NULL;
        const char *feature_id;
        Feature *f;
        int r;

        assert(argc <= 2);
        feature_id = argc >= 2 ? argv[1] : NULL;

        r = process_image(/* ro= */ true, &mounted_dir, &loop_device);
        if (r < 0)
                return r;

        r = context_make_offline(&context, loop_device ? loop_device->node : NULL, /* requires_enabled_transfers= */ false);
        if (r < 0)
                return r;

        if (feature_id) {
                _cleanup_strv_free_ char **transfers = NULL;

                f = hashmap_get(context->features, feature_id);
                if (!f)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOENT),
                                               "Optional feature not found: %s",
                                               feature_id);

                table = table_new_vertical();
                if (!table)
                        return log_oom();

                FOREACH_ARRAY(tr, context->transfers, context->n_transfers) {
                        Transfer *t = *tr;

                        if (!strv_contains(t->features, f->id) && !strv_contains(t->requisite_features, f->id))
                                continue;

                        r = strv_extend(&transfers, t->id);
                        if (r < 0)
                                return log_oom();
                }

                FOREACH_ARRAY(tr, context->disabled_transfers, context->n_disabled_transfers) {
                        Transfer *t = *tr;

                        if (!strv_contains(t->features, f->id) && !strv_contains(t->requisite_features, f->id))
                                continue;

                        r = strv_extend(&transfers, t->id);
                        if (r < 0)
                                return log_oom();
                }

                r = table_add_many(table,
                                   TABLE_FIELD, "Name",
                                   TABLE_STRING, f->id,
                                   TABLE_FIELD, "Enabled",
                                   TABLE_BOOLEAN, f->enabled);
                if (r < 0)
                        return table_log_add_error(r);

                if (f->description) {
                        r = table_add_many(table, TABLE_FIELD, "Description", TABLE_STRING, f->description);
                        if (r < 0)
                                return table_log_add_error(r);
                }

                if (f->documentation) {
                        r = table_add_many(table,
                                           TABLE_FIELD, "Documentation",
                                           TABLE_STRING, f->documentation,
                                           TABLE_SET_URL, f->documentation);
                        if (r < 0)
                                return table_log_add_error(r);
                }

                if (f->appstream) {
                        r = table_add_many(table,
                                           TABLE_FIELD, "AppStream",
                                           TABLE_STRING, f->appstream,
                                           TABLE_SET_URL, f->appstream);
                        if (r < 0)
                                return table_log_add_error(r);
                }

                if (!strv_isempty(transfers)) {
                        r = table_add_many(table, TABLE_FIELD, "Transfers", TABLE_STRV_WRAPPED, transfers);
                        if (r < 0)
                                return table_log_add_error(r);
                }

                return table_print_with_pager(table, arg_json_format_flags, arg_pager_flags, arg_legend);
        } else if (FLAGS_SET(arg_json_format_flags, SD_JSON_FORMAT_OFF)) {
                table = table_new("", "feature", "description", "documentation");
                if (!table)
                        return log_oom();

                HASHMAP_FOREACH(f, context->features) {
                        r = table_add_many(table,
                                           TABLE_BOOLEAN_CHECKMARK, f->enabled,
                                           TABLE_SET_COLOR, ansi_highlight_green_red(f->enabled),
                                           TABLE_STRING, f->id,
                                           TABLE_STRING, f->description,
                                           TABLE_STRING, f->documentation,
                                           TABLE_SET_URL, f->documentation);
                        if (r < 0)
                                return table_log_add_error(r);
                }

                return table_print_with_pager(table, arg_json_format_flags, arg_pager_flags, arg_legend);
        } else {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *json = NULL;
                _cleanup_strv_free_ char **features = NULL;

                HASHMAP_FOREACH(f, context->features) {
                        r = strv_extend(&features, f->id);
                        if (r < 0)
                                return log_oom();
                }

                r = sd_json_buildo(&json, SD_JSON_BUILD_PAIR_STRV("features", features));
                if (r < 0)
                        return log_error_errno(r, "Failed to create JSON: %m");

                r = sd_json_variant_dump(json, arg_json_format_flags, stdout, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to print JSON: %m");
        }

        return 0;
}

static int verb_check_new(int argc, char **argv, void *userdata) {
        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(umount_and_rmdir_and_freep) char *mounted_dir = NULL;
        _cleanup_(context_freep) Context* context = NULL;
        int r;

        assert(argc <= 1);

        r = process_image(/* ro= */ true, &mounted_dir, &loop_device);
        if (r < 0)
                return r;

        r = context_make_online(&context, loop_device ? loop_device->node : NULL);
        if (r < 0)
                return r;

        if (!sd_json_format_enabled(arg_json_format_flags)) {
                if (!context->candidate) {
                        log_debug("No candidate found.");
                        return EXIT_FAILURE;
                }

                puts(context->candidate->version);
        } else {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *json = NULL;

                if (context->candidate)
                        r = sd_json_buildo(&json, SD_JSON_BUILD_PAIR_STRING("available", context->candidate->version));
                else
                        r = sd_json_buildo(&json, SD_JSON_BUILD_PAIR_NULL("available"));
                if (r < 0)
                        return log_error_errno(r, "Failed to create JSON: %m");

                r = sd_json_variant_dump(json, arg_json_format_flags, stdout, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to print JSON: %m");
        }

        return EXIT_SUCCESS;
}

static int verb_vacuum(int argc, char **argv, void *userdata) {
        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(umount_and_rmdir_and_freep) char *mounted_dir = NULL;
        _cleanup_(context_freep) Context* context = NULL;
        int r;

        assert(argc <= 1);

        if (arg_instances_max < 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                      "The --instances-max argument must be >= 1 while vacuuming");

        r = process_image(/* ro= */ false, &mounted_dir, &loop_device);
        if (r < 0)
                return r;

        r = context_make_offline(&context, loop_device ? loop_device->node : NULL, /* requires_enabled_transfers= */ false);
        if (r < 0)
                return r;

        return context_vacuum(context, 0, NULL);
}

typedef enum {
        UPDATE_ACTION_ACQUIRE = 1 << 0,
        UPDATE_ACTION_INSTALL = 1 << 1,
} UpdateActionFlags;

static int verb_update_impl(int argc, char **argv, UpdateActionFlags action_flags) {
        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(umount_and_rmdir_and_freep) char *mounted_dir = NULL;
        _cleanup_(context_freep) Context* context = NULL;
        _cleanup_free_ char *booted_version = NULL;
        UpdateSet *applied = NULL;
        const char *version;
        int r;

        assert(argc <= 2);
        version = argc >= 2 ? argv[1] : NULL;

        if (arg_instances_max < 2)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                      "The --instances-max argument must be >= 2 while updating");

        if (arg_reboot) {
                /* If automatic reboot on completion is requested, let's first determine the currently booted image */

                r = parse_os_release(arg_root, "IMAGE_VERSION", &booted_version);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse /etc/os-release: %m");
                if (!booted_version)
                        return log_error_errno(SYNTHETIC_ERRNO(ENODATA), "/etc/os-release lacks IMAGE_VERSION field.");
        }

        r = process_image(/* ro= */ false, &mounted_dir, &loop_device);
        if (r < 0)
                return r;

        r = context_make_online(&context, loop_device ? loop_device->node : NULL);
        if (r < 0)
                return r;

        if (action_flags & UPDATE_ACTION_ACQUIRE)
                r = context_acquire(context, version);
        else
                r = context_process_partial_and_pending(context, version);
        if (r < 0)
                return r;  /* error */

        if (action_flags & UPDATE_ACTION_INSTALL && r > 0)  /* update needed */
                r = context_install(context, version, &applied);
        if (r < 0)
                return r;

        if (r > 0 && arg_reboot) {
                assert(applied);
                assert(booted_version);

                if (strverscmp_improved(applied->version, booted_version) > 0) {
                        log_notice("Newly installed version is newer than booted version, rebooting.");
                        return reboot_now();
                }

                if (strverscmp_improved(applied->version, booted_version) == 0 &&
                    FLAGS_SET(applied->flags, UPDATE_INCOMPLETE)) {
                        log_notice("Currently booted version was incomplete and has been repaired, rebooting.");
                        return reboot_now();
                }

                log_info("Booted version is newer or identical to newly installed version, not rebooting.");
        }

        return 0;
}

static int verb_update(int argc, char **argv, void *userdata) {
        return verb_update_impl(argc, argv, UPDATE_ACTION_ACQUIRE | UPDATE_ACTION_INSTALL);
}

static int verb_pending_or_reboot(int argc, char **argv, void *userdata) {
        _cleanup_(context_freep) Context* context = NULL;
        _cleanup_free_ char *booted_version = NULL;
        int r;

        assert(argc == 1);

        if (arg_image || arg_root)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "The --root=/--image= switches may not be combined with the '%s' operation.", argv[0]);

        r = context_make_offline(&context, /* node= */ NULL, /* requires_enabled_transfers= */ true);
        if (r < 0)
                return r;

        log_info("Determining installed update sets%s", glyph(GLYPH_ELLIPSIS));

        r = context_discover_update_sets_by_flag(context, UPDATE_INSTALLED);
        if (r < 0)
                return r;
        if (!context->newest_installed)
                return log_error_errno(SYNTHETIC_ERRNO(ENODATA), "Couldn't find any suitable installed versions.");

        r = parse_os_release(arg_root, "IMAGE_VERSION", &booted_version);
        if (r < 0) /* yes, arg_root is NULL here, but we have to pass something, and it's a lot more readable
                    * if we see what the first argument is about */
                return log_error_errno(r, "Failed to parse /etc/os-release: %m");
        if (!booted_version)
                return log_error_errno(SYNTHETIC_ERRNO(ENODATA), "/etc/os-release lacks IMAGE_VERSION= field.");

        r = strverscmp_improved(context->newest_installed->version, booted_version);
        if (r > 0) {
                log_notice("Newest installed version '%s' is newer than booted version '%s'.%s",
                           context->newest_installed->version, booted_version,
                           streq(argv[0], "pending") ? " Reboot recommended." : "");

                if (streq(argv[0], "reboot"))
                        return reboot_now();

                return EXIT_SUCCESS;
        } else if (r == 0)
                log_info("Newest installed version '%s' matches booted version '%s'.",
                         context->newest_installed->version, booted_version);
        else
                log_warning("Newest installed version '%s' is older than booted version '%s'.",
                            context->newest_installed->version, booted_version);

        if (streq(argv[0], "pending")) /* When called as 'pending' tell the caller via failure exit code that there's nothing newer installed */
                return EXIT_FAILURE;

        return EXIT_SUCCESS;
}

static int component_name_valid(const char *c) {
        _cleanup_free_ char *j = NULL;

        /* See if the specified string enclosed in the directory prefix+suffix would be a valid file name */

        if (isempty(c))
                return false;

        if (string_has_cc(c, NULL))
                return false;

        if (!utf8_is_valid(c))
                return false;

        j = strjoin("sysupdate.", c, ".d");
        if (!j)
                return -ENOMEM;

        return filename_is_valid(j);
}

static int verb_components(int argc, char **argv, void *userdata) {
        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(umount_and_rmdir_and_freep) char *mounted_dir = NULL;
        _cleanup_set_free_ Set *names = NULL;
        bool has_default_component = false;
        int r;

        assert(argc <= 1);

        r = process_image(/* ro= */ false, &mounted_dir, &loop_device);
        if (r < 0)
                return r;

        ConfFile **directories = NULL;
        size_t n_directories = 0;

        CLEANUP_ARRAY(directories, n_directories, conf_file_free_many);

        r = conf_files_list_strv_full(".d", arg_root, CONF_FILES_DIRECTORY|CONF_FILES_WARN,
                                      (const char * const *) CONF_PATHS_STRV(""), &directories, &n_directories);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate directories: %m");

        FOREACH_ARRAY(i, directories, n_directories) {
                ConfFile *e = *i;

                if (streq(e->filename, "sysupdate.d")) {
                        has_default_component = true;
                        continue;
                }

                const char *s = startswith(e->filename, "sysupdate.");
                if (!s)
                        continue;

                const char *a = endswith(s, ".d");
                if (!a)
                        continue;

                _cleanup_free_ char *n = strndup(s, a - s);
                if (!n)
                        return log_oom();

                r = component_name_valid(n);
                if (r < 0)
                        return log_error_errno(r, "Unable to validate component name '%s': %m", n);
                if (r == 0)
                        continue;

                r = set_ensure_put(&names, &string_hash_ops_free, n);
                if (r < 0 && r != -EEXIST)
                        return log_error_errno(r, "Failed to add component '%s' to set: %m", n);
                TAKE_PTR(n);
        }

        /* We use simple free() rather than strv_free() here, since set_free() will free the strings for us */
        _cleanup_free_ char **z = set_get_strv(names);
        if (!z)
                return log_oom();

        strv_sort(z);

        if (!sd_json_format_enabled(arg_json_format_flags)) {
                if (!has_default_component && set_isempty(names)) {
                        log_info("No components defined.");
                        return 0;
                }

                if (has_default_component)
                        printf("%s<default>%s\n",
                               ansi_highlight(), ansi_normal());

                STRV_FOREACH(i, z)
                        puts(*i);
        } else {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *json = NULL;

                r = sd_json_buildo(&json, SD_JSON_BUILD_PAIR_BOOLEAN("default", has_default_component),
                                          SD_JSON_BUILD_PAIR_STRV("components", z));
                if (r < 0)
                        return log_error_errno(r, "Failed to create JSON: %m");

                r = sd_json_variant_dump(json, arg_json_format_flags, stdout, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to print JSON: %m");
        }

        return 0;
}

static int verb_help(int argc, char **argv, void *userdata) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-sysupdate", "8", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTIONS...] [VERSION]\n"
               "\n%5$sUpdate OS images.%6$s\n"
               "\n%3$sCommands:%4$s\n"
               "  list [VERSION]          Show installed and available versions\n"
               "  features [FEATURE]      Show optional features\n"
               "  check-new               Check if there's a new version available\n"
               "  update [VERSION]        Install new version now\n"
               "  vacuum                  Make room, by deleting old versions\n"
               "  pending                 Report whether a newer version is installed than\n"
               "                          currently booted\n"
               "  reboot                  Reboot if a newer version is installed than booted\n"
               "  components              Show list of components\n"
               "  -h --help               Show this help\n"
               "     --version            Show package version\n"
               "\n%3$sOptions:%4$s\n"
               "  -C --component=NAME     Select component to update\n"
               "     --definitions=DIR    Find transfer definitions in specified directory\n"
               "     --root=PATH          Operate on an alternate filesystem root\n"
               "     --image=PATH         Operate on disk image as filesystem root\n"
               "     --image-policy=POLICY\n"
               "                          Specify disk image dissection policy\n"
               "  -m --instances-max=INT  How many instances to maintain\n"
               "     --sync=BOOL          Controls whether to sync data to disk\n"
               "     --verify=BOOL        Force signature verification on or off\n"
               "     --reboot             Reboot after updating to newer version\n"
               "     --offline            Do not fetch metadata from the network\n"
               "     --no-pager           Do not pipe output into a pager\n"
               "     --no-legend          Do not show the headers and footers\n"
               "     --json=pretty|short|off\n"
               "                          Generate JSON output\n"
               "     --transfer-source=PATH\n"
               "                          Specify the directory to transfer sources from\n"
               "\nSee the %2$s for details.\n",
               program_invocation_short_name,
               link,
               ansi_underline(),
               ansi_normal(),
               ansi_highlight(),
               ansi_normal());

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_NO_PAGER,
                ARG_NO_LEGEND,
                ARG_SYNC,
                ARG_DEFINITIONS,
                ARG_JSON,
                ARG_ROOT,
                ARG_IMAGE,
                ARG_IMAGE_POLICY,
                ARG_REBOOT,
                ARG_VERIFY,
                ARG_OFFLINE,
                ARG_TRANSFER_SOURCE,
        };

        static const struct option options[] = {
                { "help",              no_argument,       NULL, 'h'                   },
                { "version",           no_argument,       NULL, ARG_VERSION           },
                { "no-pager",          no_argument,       NULL, ARG_NO_PAGER          },
                { "no-legend",         no_argument,       NULL, ARG_NO_LEGEND         },
                { "definitions",       required_argument, NULL, ARG_DEFINITIONS       },
                { "instances-max",     required_argument, NULL, 'm'                   },
                { "sync",              required_argument, NULL, ARG_SYNC              },
                { "json",              required_argument, NULL, ARG_JSON              },
                { "root",              required_argument, NULL, ARG_ROOT              },
                { "image",             required_argument, NULL, ARG_IMAGE             },
                { "image-policy",      required_argument, NULL, ARG_IMAGE_POLICY      },
                { "reboot",            no_argument,       NULL, ARG_REBOOT            },
                { "component",         required_argument, NULL, 'C'                   },
                { "verify",            required_argument, NULL, ARG_VERIFY            },
                { "offline",           no_argument,       NULL, ARG_OFFLINE           },
                { "transfer-source",   required_argument, NULL, ARG_TRANSFER_SOURCE   },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hm:C:", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        return verb_help(0, NULL, NULL);

                case ARG_VERSION:
                        return version();

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case ARG_NO_LEGEND:
                        arg_legend = false;
                        break;

                case 'm':
                        r = safe_atou64(optarg, &arg_instances_max);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --instances-max= parameter: %s", optarg);

                        break;

                case ARG_SYNC:
                        r = parse_boolean_argument("--sync=", optarg, &arg_sync);
                        if (r < 0)
                                return r;
                        break;

                case ARG_DEFINITIONS:
                        r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_definitions);
                        if (r < 0)
                                return r;
                        break;

                case ARG_JSON:
                        r = parse_json_argument(optarg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;

                        break;

                case ARG_ROOT:
                        r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_root);
                        if (r < 0)
                                return r;
                        break;

                case ARG_IMAGE:
                        r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_image);
                        if (r < 0)
                                return r;
                        break;

                case ARG_IMAGE_POLICY:
                        r = parse_image_policy_argument(optarg, &arg_image_policy);
                        if (r < 0)
                                return r;
                        break;

                case ARG_REBOOT:
                        arg_reboot = true;
                        break;

                case 'C':
                        if (isempty(optarg)) {
                                arg_component = mfree(arg_component);
                                break;
                        }

                        r = component_name_valid(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to determine if component name is valid: %m");
                        if (r == 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Component name invalid: %s", optarg);

                        r = free_and_strdup_warn(&arg_component, optarg);
                        if (r < 0)
                                return r;

                        break;

                case ARG_VERIFY: {
                        bool b;

                        r = parse_boolean_argument("--verify=", optarg, &b);
                        if (r < 0)
                                return r;

                        arg_verify = b;
                        break;
                }

                case ARG_OFFLINE:
                        arg_offline = true;
                        break;

                case ARG_TRANSFER_SOURCE:
                        r = parse_path_argument(optarg, /* suppress_root= */ false, &arg_transfer_source);
                        if (r < 0)
                                return r;

                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }
        }

        if (arg_image && arg_root)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Please specify either --root= or --image=, the combination of both is not supported.");

        if ((arg_image || arg_root) && arg_reboot)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "The --reboot switch may not be combined with --root= or --image=.");

        if (arg_definitions && arg_component)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "The --definitions= and --component= switches may not be combined.");

        return 1;
}

static int sysupdate_main(int argc, char *argv[]) {

        static const Verb verbs[] = {
                { "list",       VERB_ANY, 2, VERB_DEFAULT, verb_list              },
                { "components", VERB_ANY, 1, 0,            verb_components        },
                { "features",   VERB_ANY, 2, 0,            verb_features          },
                { "check-new",  VERB_ANY, 1, 0,            verb_check_new         },
                { "update",     VERB_ANY, 2, 0,            verb_update            },
                { "vacuum",     VERB_ANY, 1, 0,            verb_vacuum            },
                { "reboot",     1,        1, 0,            verb_pending_or_reboot },
                { "pending",    1,        1, 0,            verb_pending_or_reboot },
                { "help",       VERB_ANY, 1, 0,            verb_help              },
                {}
        };

        return dispatch_verb(argc, argv, verbs, NULL);
}

static int run(int argc, char *argv[]) {
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        return sysupdate_main(argc, argv);
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
