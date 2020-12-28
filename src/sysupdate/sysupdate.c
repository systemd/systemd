/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>
#include <unistd.h>

#include "bus-error.h"
#include "bus-locator.h"
#include "chase-symlinks.h"
#include "conf-files.h"
#include "def.h"
#include "dirent-util.h"
#include "dissect-image.h"
#include "fd-util.h"
#include "format-table.h"
#include "glyph-util.h"
#include "hexdecoct.h"
#include "login-util.h"
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
#include "string-util.h"
#include "strv.h"
#include "sysupdate-transfer.h"
#include "sysupdate-update-set.h"
#include "sysupdate.h"
#include "terminal-util.h"
#include "utf8.h"
#include "verbs.h"

static char *arg_definitions = NULL;
bool arg_sync = true;
uint64_t arg_instances_max = UINT64_MAX;
static JsonFormatFlags arg_json_format_flags = JSON_FORMAT_OFF;
static PagerFlags arg_pager_flags = 0;
static bool arg_legend = true;
char *arg_root = NULL;
static char *arg_image = NULL;
static bool arg_reboot = false;
static char *arg_component = NULL;
static int arg_verify = -1;

STATIC_DESTRUCTOR_REGISTER(arg_definitions, freep);
STATIC_DESTRUCTOR_REGISTER(arg_root, freep);
STATIC_DESTRUCTOR_REGISTER(arg_image, freep);
STATIC_DESTRUCTOR_REGISTER(arg_component, freep);

typedef struct Context {
        Transfer **transfers;
        size_t n_transfers;

        UpdateSet **update_sets;
        size_t n_update_sets;

        UpdateSet *newest_installed, *candidate;

        Hashmap *web_cache; /* Cache for downloaded resources, keyed by URL */
} Context;

static Context *context_free(Context *c) {
        if (!c)
                return NULL;

        for (size_t i = 0; i < c->n_transfers; i++)
                transfer_free(c->transfers[i]);
        free(c->transfers);

        for (size_t i = 0; i < c->n_update_sets; i++)
                update_set_free(c->update_sets[i]);
        free(c->update_sets);

        hashmap_free(c->web_cache);

        return mfree(c);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Context*, context_free);

static Context *context_new(void) {
        /* For now, no fields to initialize non-zero */
        return new0(Context, 1);
}

static int context_read_definitions(
                Context *c,
                const char *directory,
                const char *component,
                const char *root,
                const char *node) {

        _cleanup_strv_free_ char **files = NULL;
        char **f;
        int r;

        assert(c);

        if (directory)
                r = conf_files_list_strv(&files, ".conf", NULL, CONF_FILES_REGULAR|CONF_FILES_FILTER_MASKED, (const char**) STRV_MAKE(directory));
        else if (component) {
                _cleanup_strv_free_ char **n = NULL;
                char **l = CONF_PATHS_STRV(""), **i;
                size_t k = 0;

                n = new0(char*, strv_length(l) + 1);
                if (!n)
                        return log_oom();

                STRV_FOREACH(i, l) {
                        char *j;

                        j = strjoin(*i, "sysupdate.", component, ".d");
                        if (!j)
                                return log_oom();

                        n[k++] = j;
                }

                r = conf_files_list_strv(&files, ".conf", root, CONF_FILES_REGULAR|CONF_FILES_FILTER_MASKED, (const char**) n);
        } else
                r = conf_files_list_strv(&files, ".conf", root, CONF_FILES_REGULAR|CONF_FILES_FILTER_MASKED, (const char**) CONF_PATHS_STRV("sysupdate.d"));
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate *.conf files: %m");

        STRV_FOREACH(f, files) {
                _cleanup_(transfer_freep) Transfer *t = NULL;

                if (!GREEDY_REALLOC(c->transfers, c->n_transfers + 1))
                        return log_oom();

                t = transfer_new();
                if (!t)
                        return log_oom();

                t->definition_path = strdup(*f);
                if (!t->definition_path)
                        return log_oom();

                r = transfer_read_definition(t, *f);
                if (r < 0)
                        return r;

                c->transfers[c->n_transfers++] = TAKE_PTR(t);
        }

        if (c->n_transfers == 0) {
                if (arg_component)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOENT),
                                               "No transfer definitions for component '%s' found.", arg_component);

                return log_error_errno(SYNTHETIC_ERRNO(ENOENT),
                                       "No transfer definitions found.");
        }

        for (size_t i = 0; i < c->n_transfers; i++) {
                r = transfer_resolve_paths(c->transfers[i], root, node);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int context_load_installed_instances(Context *c) {
        int r;

        assert(c);

        log_info("Discovering installed instances…");

        for (size_t i = 0; i < c->n_transfers; i++) {
                r = resource_load_instances(
                                &c->transfers[i]->target,
                                arg_verify >= 0 ? arg_verify : c->transfers[i]->verify,
                                &c->web_cache);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int context_load_available_instances(Context *c) {
        int r;

        assert(c);

        log_info("Discovering available instances…");

        for (size_t i = 0; i < c->n_transfers; i++) {
                assert(c->transfers[i]);

                r = resource_load_instances(
                                &c->transfers[i]->source,
                                arg_verify >= 0 ? arg_verify : c->transfers[i]->verify,
                                &c->web_cache);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int context_discover_update_sets_by_flag(Context *c, UpdateSetFlags flags) {
        _cleanup_free_ Instance **cursor_instances = NULL;
        _cleanup_free_ char *boundary = NULL;
        bool newest_found = false;
        int r;

        assert(c);
        assert(IN_SET(flags, UPDATE_AVAILABLE, UPDATE_INSTALLED));

        for (;;) {
                bool incomplete = false, exists = false;
                UpdateSetFlags extra_flags = 0;
                _cleanup_free_ char *cursor = NULL;
                UpdateSet *us = NULL;

                for (size_t k = 0; k < c->n_transfers; k++) {
                        Transfer *t = c->transfers[k];
                        bool cursor_found = false;
                        Resource *rr;

                        assert(t);

                        if (flags == UPDATE_AVAILABLE)
                                rr = &t->source;
                        else {
                                assert(flags == UPDATE_INSTALLED);
                                rr = &t->target;
                        }

                        for (size_t j = 0; j < rr->n_instances; j++) {
                                Instance *i = rr->instances[j];

                                assert(i);

                                /* Is the instance we are looking at equal or newer than the boundary? If so, we
                                 * already checked this version, and it wasn't complete, let's ignore it. */
                                if (boundary && strverscmp_improved(i->metadata.version, boundary) >= 0)
                                        continue;

                                if (cursor) {
                                        if (strverscmp_improved(i->metadata.version, cursor) != 0)
                                                continue;
                                } else {
                                        cursor = strdup(i->metadata.version);
                                        if (!cursor)
                                                return log_oom();
                                }

                                cursor_found = true;

                                if (!cursor_instances) {
                                        cursor_instances = new(Instance*, c->n_transfers);
                                        if (!cursor_instances)
                                                return -ENOMEM;
                                }
                                cursor_instances[k] = i;
                                break;
                        }

                        if (!cursor) /* No suitable instance beyond the boundary found? Then we are done! */
                                break;

                        if (!cursor_found) {
                                /* Hmm, we didn't find the version indicated by 'cursor' among the instances
                                 * of this transfer, let's skip it. */
                                incomplete = true;
                                break;
                        }

                        if (t->min_version && strverscmp_improved(t->min_version, cursor) > 0)
                                extra_flags |= UPDATE_OBSOLETE;

                        if (strv_contains(t->protected_versions, cursor))
                                extra_flags |= UPDATE_PROTECTED;
                }

                if (!cursor) /* EOL */
                        break;

                r = free_and_strdup_warn(&boundary, cursor);
                if (r < 0)
                        return r;

                if (incomplete) /* One transfer was missing this version, ignore the whole thing */
                        continue;

                /* See if we already have this update set in our table */
                for (size_t i = 0; i < c->n_update_sets; i++) {
                        if (strverscmp_improved(c->update_sets[i]->version, cursor) != 0)
                                continue;

                        /* We only store the instances we found first, but we remember we also found it again */
                        c->update_sets[i]->flags |= flags | extra_flags;
                        exists = true;
                        newest_found = true;
                        break;
                }

                if (exists)
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

                /* Remember which is the newest non-obsolete, available (and not installed) version, which we declare the "candidate" */
                if ((us->flags & (UPDATE_NEWEST|UPDATE_INSTALLED|UPDATE_AVAILABLE|UPDATE_OBSOLETE)) == (UPDATE_NEWEST|UPDATE_AVAILABLE))
                        c->candidate = us;
        }

        /* Newest installed is newer than or equal to candidate? Then suppress the candidate */
        if (c->newest_installed && c->candidate && strverscmp_improved(c->newest_installed->version, c->candidate->version) >= 0)
                c->candidate = NULL;

        return 0;
}

static int context_discover_update_sets(Context *c) {
        int r;

        assert(c);

        log_info("Determining installed update sets…");

        r = context_discover_update_sets_by_flag(c, UPDATE_INSTALLED);
        if (r < 0)
                return r;

        log_info("Determining available update sets…");

        r = context_discover_update_sets_by_flag(c, UPDATE_AVAILABLE);
        if (r < 0)
                return r;

        typesafe_qsort(c->update_sets, c->n_update_sets, update_set_cmp);
        return 0;
}

static const char *update_set_flags_to_string(UpdateSetFlags flags) {

        switch ((unsigned) flags) {

        case 0:
                return "n/a";

        case UPDATE_INSTALLED|UPDATE_NEWEST:
        case UPDATE_INSTALLED|UPDATE_NEWEST|UPDATE_PROTECTED:
        case UPDATE_INSTALLED|UPDATE_AVAILABLE|UPDATE_NEWEST:
        case UPDATE_INSTALLED|UPDATE_AVAILABLE|UPDATE_NEWEST|UPDATE_PROTECTED:
                return "current";

        case UPDATE_AVAILABLE|UPDATE_NEWEST:
        case UPDATE_AVAILABLE|UPDATE_NEWEST|UPDATE_PROTECTED:
                return "candidate";

        case UPDATE_INSTALLED:
        case UPDATE_INSTALLED|UPDATE_AVAILABLE:
                return "installed";

        case UPDATE_INSTALLED|UPDATE_PROTECTED:
        case UPDATE_INSTALLED|UPDATE_AVAILABLE|UPDATE_PROTECTED:
                return "protected";

        case UPDATE_AVAILABLE:
        case UPDATE_AVAILABLE|UPDATE_PROTECTED:
                return "available";

        case UPDATE_INSTALLED|UPDATE_OBSOLETE|UPDATE_NEWEST:
        case UPDATE_INSTALLED|UPDATE_OBSOLETE|UPDATE_NEWEST|UPDATE_PROTECTED:
        case UPDATE_INSTALLED|UPDATE_AVAILABLE|UPDATE_OBSOLETE|UPDATE_NEWEST:
        case UPDATE_INSTALLED|UPDATE_AVAILABLE|UPDATE_OBSOLETE|UPDATE_NEWEST|UPDATE_PROTECTED:
                return "current+obsolete";

        case UPDATE_INSTALLED|UPDATE_OBSOLETE:
        case UPDATE_INSTALLED|UPDATE_AVAILABLE|UPDATE_OBSOLETE:
                return "installed+obsolete";

        case UPDATE_INSTALLED|UPDATE_OBSOLETE|UPDATE_PROTECTED:
        case UPDATE_INSTALLED|UPDATE_AVAILABLE|UPDATE_OBSOLETE|UPDATE_PROTECTED:
                return "protected+obsolete";

        case UPDATE_AVAILABLE|UPDATE_OBSOLETE:
        case UPDATE_AVAILABLE|UPDATE_OBSOLETE|UPDATE_PROTECTED:
        case UPDATE_AVAILABLE|UPDATE_OBSOLETE|UPDATE_NEWEST:
        case UPDATE_AVAILABLE|UPDATE_OBSOLETE|UPDATE_NEWEST|UPDATE_PROTECTED:
                return "available+obsolete";

        default:
                assert_not_reached();
        }
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

        for (size_t i = 0; i < c->n_update_sets; i++) {
                UpdateSet *us = c->update_sets[i];
                const char *color;

                color = update_set_flags_to_color(us->flags);

                r = table_add_many(t,
                                   TABLE_STRING,    update_set_flags_to_glyph(us->flags),
                                   TABLE_SET_COLOR, color,
                                   TABLE_STRING,    us->version,
                                   TABLE_SET_COLOR, color,
                                   TABLE_STRING,    special_glyph_check_mark_space(FLAGS_SET(us->flags, UPDATE_INSTALLED)),
                                   TABLE_SET_COLOR, color,
                                   TABLE_STRING,    special_glyph_check_mark_space(FLAGS_SET(us->flags, UPDATE_AVAILABLE)),
                                   TABLE_SET_COLOR, color,
                                   TABLE_STRING,    update_set_flags_to_string(us->flags),
                                   TABLE_SET_COLOR, color);
                if (r < 0)
                        return table_log_add_error(r);
        }

        return table_print_with_pager(t, arg_json_format_flags, arg_pager_flags, arg_legend);
}

static UpdateSet *context_update_set_by_version(Context *c, const char *version) {
        assert(c);
        assert(version);

        for (size_t i = 0; i < c->n_update_sets; i++)
                if (streq(c->update_sets[i]->version, version))
                        return c->update_sets[i];

        return NULL;
}

static int context_show_version(Context *c, const char *version) {
        bool show_fs_columns = false, show_partition_columns = false,
                have_fs_attributes = false, have_partition_attributes = false,
                have_size = false, have_tries = false, have_no_auto = false,
                have_read_only = false, have_growfs = false, have_sha256 = false;
        _cleanup_(table_unrefp) Table *t = NULL;
        UpdateSet *us;
        int r;

        assert(c);
        assert(version);

        us = context_update_set_by_version(c, version);
        if (!us)
                return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "Update '%s' not found.", version);

        if (arg_json_format_flags & (JSON_FORMAT_OFF|JSON_FORMAT_PRETTY|JSON_FORMAT_PRETTY_AUTO))
                (void) pager_open(arg_pager_flags);

        if (FLAGS_SET(arg_json_format_flags, JSON_FORMAT_OFF))
                printf("%s%s%s Version: %s\n"
                       "    State: %s%s%s\n"
                       "Installed: %s%s\n"
                       "Available: %s%s\n"
                       "Protected: %s%s%s\n"
                       " Obsolete: %s%s%s\n\n",
                       strempty(update_set_flags_to_color(us->flags)), update_set_flags_to_glyph(us->flags), ansi_normal(), us->version,
                       strempty(update_set_flags_to_color(us->flags)), update_set_flags_to_string(us->flags), ansi_normal(),
                       yes_no(us->flags & UPDATE_INSTALLED), FLAGS_SET(us->flags, UPDATE_INSTALLED|UPDATE_NEWEST) ? " (newest)" : "",
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
        (void) table_set_empty_string(t, "-");

        /* Determine if the target will make use of partition/fs attributes for any of the transfers */
        for (size_t n = 0; n < c->n_transfers; n++) {
                Transfer *tr = c->transfers[n];

                if (tr->target.type == RESOURCE_PARTITION)
                        show_partition_columns = true;
                if (RESOURCE_IS_FILESYSTEM(tr->target.type))
                        show_fs_columns = true;
        }

        for (size_t n = 0; n < us->n_instances; n++) {
                Instance *i = us->instances[n];

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

        return table_print_with_pager(t, arg_json_format_flags, arg_pager_flags, arg_legend);
}

static int context_vacuum(
                Context *c,
                uint64_t space,
                const char *extra_protected_version) {

        int r, count = 0;

        assert(c);

        if (space == 0)
                log_info("Making room…");
        else
                log_info("Making room for %" PRIu64 " updates…", space);

        for (size_t i = 0; i < c->n_transfers; i++) {
                r = transfer_vacuum(c->transfers[i], space, extra_protected_version);
                if (r < 0)
                        return r;

                count = MAX(count, r);
        }

        if (count > 0)
                log_info("Removed %i instances.", count);
        else
                log_info("Removed no instances.");

        return 0;
}

static int context_make_offline(Context **ret, const char *node) {
        _cleanup_(context_freep) Context* context = NULL;
        int r;

        assert(ret);

        /* Allocates a context object and initializes everything we can initialize offline, i.e. without
         * checking on the update source (i.e. the Internet) what versions are available */

        context = context_new();
        if (!context)
                return log_oom();

        r = context_read_definitions(context, arg_definitions, arg_component, arg_root, node);
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
         * versions. */

        r = context_make_offline(&context, node);
        if (r < 0)
                return r;

        r = context_load_available_instances(context);
        if (r < 0)
                return r;

        r = context_discover_update_sets(context);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(context);
        return 0;
}

static int context_apply(
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

                        if (ret_applied)
                                *ret_applied = NULL;

                        return 0;
                }

                us = c->candidate;
        }

        if (FLAGS_SET(us->flags, UPDATE_INSTALLED)) {
                log_info("Selected update '%s' is already installed. Skipping update.", us->version);

                if (ret_applied)
                        *ret_applied = NULL;

                return 0;
        }
        if (!FLAGS_SET(us->flags, UPDATE_AVAILABLE))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Selected update '%s' is not available, refusing.", us->version);
        if (FLAGS_SET(us->flags, UPDATE_OBSOLETE))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Selected update '%s' is obsolete, refusing.", us->version);

        assert((us->flags & (UPDATE_AVAILABLE|UPDATE_INSTALLED|UPDATE_OBSOLETE)) == UPDATE_AVAILABLE);

        if (!FLAGS_SET(us->flags, UPDATE_NEWEST))
                log_notice("Selected update '%s' is not the newest, proceeding anyway.", us->version);
        if (c->newest_installed && strverscmp_improved(c->newest_installed->version, us->version) > 0)
                log_notice("Selected update '%s' is older than newest installed version, proceeding anyway.", us->version);

        log_info("Selected update '%s' for install.", us->version);

        (void) sd_notifyf(false,
                          "STATUS=Making room for '%s'.", us->version);

        /* Let's make some room. We make sure for each transfer we have one free space to fill. While
         * removing stuff we'll protect the version we are trying to acquire. Why that? Maybe an earlier
         * download succeeded already, in which case we shouldn't remove it just to acquire it again */
        r = context_vacuum(
                        c,
                        /* space = */ 1,
                        /* extra_protected_version = */ us->version);
        if (r < 0)
                return r;

        if (arg_sync)
                sync();

        (void) sd_notifyf(false,
                          "STATUS=Updating to '%s'.\n", us->version);

        /* There should now be one instance picked for each transfer, and the order is the same */
        assert(us->n_instances == c->n_transfers);

        for (size_t i = 0; i < c->n_transfers; i++) {
                r = transfer_acquire_instance(c->transfers[i], us->instances[i]);
                if (r < 0)
                        return r;
        }

        if (arg_sync)
                sync();

        for (size_t i = 0; i < c->n_transfers; i++) {
                r = transfer_install_instance(c->transfers[i], us->instances[i], arg_root);
                if (r < 0)
                        return r;
        }

        log_info("%s Successfully installed update '%s'.", special_glyph(SPECIAL_GLYPH_SPARKLES), us->version);

        if (ret_applied)
                *ret_applied = us;

        return 1;
}

static int reboot_now(void) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_close_unrefp) sd_bus *bus = NULL;
        int r;

        r = sd_bus_open_system(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to open bus connection: %m");

        r = bus_call_method(bus, bus_login_mgr, "RebootWithFlags", &error, NULL, "t",
                            (uint64_t) SD_LOGIND_ROOT_CHECK_INHIBITORS);
        if (r < 0)
                return log_error_errno(r, "Failed to issue reboot request: %s", bus_error_message(&error, r));

        return 0;
}

static int process_image(
                bool ro,
                char **ret_mounted_dir,
                LoopDevice **ret_loop_device,
                DecryptedImage **ret_decrypted_image) {

        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(decrypted_image_unrefp) DecryptedImage *decrypted_image = NULL;
        _cleanup_(umount_and_rmdir_and_freep) char *mounted_dir = NULL;
        int r;

        assert(ret_mounted_dir);
        assert(ret_loop_device);
        assert(ret_decrypted_image);

        if (!arg_image)
                return 0;

        assert(!arg_root);

        r = mount_image_privately_interactively(
                        arg_image,
                        (ro ? DISSECT_IMAGE_READ_ONLY : 0) |
                        DISSECT_IMAGE_FSCK |
                        DISSECT_IMAGE_MKDIR |
                        DISSECT_IMAGE_GROWFS |
                        DISSECT_IMAGE_RELAX_VAR_CHECK |
                        DISSECT_IMAGE_USR_NO_ROOT |
                        DISSECT_IMAGE_GENERIC_ROOT |
                        DISSECT_IMAGE_REQUIRE_ROOT,
                        &mounted_dir,
                        &loop_device,
                        &decrypted_image);
        if (r < 0)
                return r;

        arg_root = strdup(mounted_dir);
        if (!arg_root)
                return log_oom();

        *ret_mounted_dir = TAKE_PTR(mounted_dir);
        *ret_loop_device = TAKE_PTR(loop_device);
        *ret_decrypted_image = TAKE_PTR(decrypted_image);

        return 0;
}

static int verb_list(int argc, char **argv, void *userdata) {
        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(decrypted_image_unrefp) DecryptedImage *decrypted_image = NULL;
        _cleanup_(umount_and_rmdir_and_freep) char *mounted_dir = NULL;
        _cleanup_(context_freep) Context* context = NULL;
        const char *version;
        int r;

        assert(argc <= 2);
        version = argc >= 2 ? argv[1] : NULL;

        r = process_image(/* ro= */ true, &mounted_dir, &loop_device, &decrypted_image);
        if (r < 0)
                return r;

        r = context_make_online(&context, loop_device ? loop_device->node : NULL);
        if (r < 0)
                return r;

        if (version)
                return context_show_version(context, version);
        else
                return context_show_table(context);
}

static int verb_check_new(int argc, char **argv, void *userdata) {
        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(decrypted_image_unrefp) DecryptedImage *decrypted_image = NULL;
        _cleanup_(umount_and_rmdir_and_freep) char *mounted_dir = NULL;
        _cleanup_(context_freep) Context* context = NULL;
        int r;

        assert(argc <= 1);

        r = process_image(/* ro= */ true, &mounted_dir, &loop_device, &decrypted_image);
        if (r < 0)
                return r;

        r = context_make_online(&context, loop_device ? loop_device->node : NULL);
        if (r < 0)
                return r;

        if (!context->candidate) {
                log_debug("No candidate found.");
                return EXIT_FAILURE;
        }

        puts(context->candidate->version);
        return EXIT_SUCCESS;
}

static int verb_vacuum(int argc, char **argv, void *userdata) {
        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(decrypted_image_unrefp) DecryptedImage *decrypted_image = NULL;
        _cleanup_(umount_and_rmdir_and_freep) char *mounted_dir = NULL;
        _cleanup_(context_freep) Context* context = NULL;
        int r;

        assert(argc <= 1);

        r = process_image(/* ro= */ false, &mounted_dir, &loop_device, &decrypted_image);
        if (r < 0)
                return r;

        r = context_make_offline(&context, loop_device ? loop_device->node : NULL);
        if (r < 0)
                return r;

        return context_vacuum(context, 0, NULL);
}

static int verb_update(int argc, char **argv, void *userdata) {
        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(decrypted_image_unrefp) DecryptedImage *decrypted_image = NULL;
        _cleanup_(umount_and_rmdir_and_freep) char *mounted_dir = NULL;
        _cleanup_(context_freep) Context* context = NULL;
        _cleanup_free_ char *booted_version = NULL;
        UpdateSet *applied = NULL;
        const char *version;
        int r;

        assert(argc <= 2);
        version = argc >= 2 ? argv[1] : NULL;

        if (arg_reboot) {
                /* If automatic reboot on completion is requested, let's first determine the currently booted image */

                r = parse_os_release(arg_root, "IMAGE_VERSION", &booted_version);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse /etc/os-release: %m");
                if (!booted_version)
                        return log_error_errno(SYNTHETIC_ERRNO(ENODATA), "/etc/os-release lacks IMAGE_VERSION field.");
        }

        r = process_image(/* ro= */ false, &mounted_dir, &loop_device, &decrypted_image);
        if (r < 0)
                return r;

        r = context_make_online(&context, loop_device ? loop_device->node : NULL);
        if (r < 0)
                return r;

        r = context_apply(context, version, &applied);
        if (r < 0)
                return r;

        if (r > 0 && arg_reboot) {
                assert(applied);
                assert(booted_version);

                if (strverscmp_improved(applied->version, booted_version) > 0) {
                        log_notice("Newly installed version is newer than booted version, rebooting.");
                        return reboot_now();
                }

                log_info("Booted version is newer or identical to newly installed version, not rebooting.");
        }

        return 0;
}

static int verb_pending_or_reboot(int argc, char **argv, void *userdata) {
        _cleanup_(context_freep) Context* context = NULL;
        _cleanup_free_ char *booted_version = NULL;
        int r;

        assert(argc == 1);

        if (arg_image || arg_root)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "The --root=/--image switches may not be combined with the '%s' operation.", argv[0]);

        r = context_make_offline(&context, NULL);
        if (r < 0)
                return r;

        log_info("Determining installed update sets…");

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
        _cleanup_(decrypted_image_unrefp) DecryptedImage *decrypted_image = NULL;
        _cleanup_(umount_and_rmdir_and_freep) char *mounted_dir = NULL;
        _cleanup_(set_freep) Set *names = NULL;
        _cleanup_free_ char **z = NULL; /* We use simple free() rather than strv_free() here, since set_free() will free the strings for us */
        char **l = CONF_PATHS_STRV(""), **i;
        bool has_default_component = false;
        int r;

        assert(argc <= 1);

        r = process_image(/* ro= */ false, &mounted_dir, &loop_device, &decrypted_image);
        if (r < 0)
                return r;

        STRV_FOREACH(i, l) {
                _cleanup_closedir_ DIR *d = NULL;
                _cleanup_free_ char *p = NULL;

                r = chase_symlinks_and_opendir(*i, arg_root, CHASE_PREFIX_ROOT, &p, &d);
                if (r == -ENOENT)
                        continue;
                if (r < 0)
                        return log_error_errno(r, "Failed to open directory '%s': %m", *i);

                for (;;) {
                        _cleanup_free_ char *n = NULL;
                        struct dirent *de;
                        const char *e, *a;

                        de = readdir_ensure_type(d);
                        if (!de) {
                                if (errno != 0)
                                        return log_error_errno(errno, "Failed to enumerate directory '%s': %m", p);

                                break;
                        }

                        if (de->d_type != DT_DIR)
                                continue;

                        if (dot_or_dot_dot(de->d_name))
                                continue;

                        if (streq(de->d_name, "sysupdate.d")) {
                                has_default_component = true;
                                continue;
                        }

                        e = startswith(de->d_name, "sysupdate.");
                        if (!e)
                                continue;

                        a = endswith(e, ".d");
                        if (!a)
                                continue;

                        n = strndup(e, a - e);
                        if (!n)
                                return log_oom();

                        r = component_name_valid(n);
                        if (r < 0)
                                return log_error_errno(r, "Unable to validate component name: %m");
                        if (r == 0)
                                continue;

                        r = set_ensure_consume(&names, &string_hash_ops_free, TAKE_PTR(n));
                        if (r < 0 && r != -EEXIST)
                                return log_error_errno(r, "Failed to add component to set: %m");
                }
        }

        if (!has_default_component && set_isempty(names)) {
                log_info("No components defined.");
                return 0;
        }

        z = set_get_strv(names);
        if (!z)
                return log_oom();

        strv_sort(z);

        if (has_default_component)
                printf("%s<default>%s\n",
                       ansi_highlight(), ansi_normal());

        STRV_FOREACH(i, z)
                puts(*i);

        return 0;
}

static int verb_help(int argc, char **argv, void *userdata) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("systemd-sysupdate", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%1$s [OPTIONS...] [VERSION]\n"
               "\n%5$sUpdate OS images.%6$s\n"
               "\n%3$sCommands:%4$s\n"
               "  list [VERSION]          Show installed and available versions\n"
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
               "     --root=PATH          Operate relative to root path\n"
               "     --image=PATH         Operate relative to image file\n"
               "  -m --instances-max=INT  How many instances to maintain\n"
               "     --sync=BOOL          Controls whether to sync data to disk\n"
               "     --verify=BOOL        Force signature verification on or off\n"
               "     --reboot             Reboot after updating to newer version\n"
               "     --no-pager           Do not pipe output into a pager\n"
               "     --no-legend          Do not show the headers and footers\n"
               "     --json=pretty|short|off\n"
               "                          Generate JSON output\n"
               "\nSee the %2$s for details.\n"
               , program_invocation_short_name
               , link
               , ansi_underline(), ansi_normal()
               , ansi_highlight(), ansi_normal()
        );

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
                ARG_REBOOT,
                ARG_VERIFY,
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
                { "reboot",            no_argument,       NULL, ARG_REBOOT            },
                { "component",         required_argument, NULL, 'C'                   },
                { "verify",            required_argument, NULL, ARG_VERIFY            },
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
                { "check-new",  VERB_ANY, 1, 0,            verb_check_new         },
                { "update",     VERB_ANY, 2, 0,            verb_update               },
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
