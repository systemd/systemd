/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-bus.h"
#include "sd-daemon.h"
#include "sd-json.h"
#include "sd-varlink.h"

#include "build.h"
#include "bus-polkit.h"
#include "condition.h"
#include "conf-files.h"
#include "conf-parser.h"
#include "constants.h"
#include "discover-image.h"
#include "dissect-image.h"
#include "dlopen-note.h"
#include "dropin.h"
#include "env-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "format-table.h"
#include "glyph-util.h"
#include "hashmap.h"
#include "help-util.h"
#include "hexdecoct.h"
#include "image-policy.h"
#include "json-util.h"
#include "loop-util.h"
#include "main-func.h"
#include "mount-util.h"
#include "options.h"
#include "os-util.h"
#include "pager.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "path-util.h"
#include "pretty-print.h"
#include "runtime-scope.h"
#include "set.h"
#include "siphash24.h"
#include "sort-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "sysupdate.h"
#include "sysupdate-cleanup.h"
#include "sysupdate-config.h"
#include "sysupdate-feature.h"
#include "sysupdate-instance.h"
#include "sysupdate-target.h"
#include "sysupdate-transfer.h"
#include "sysupdate-update-set.h"
#include "sysupdate-util.h"
#include "varlink-io.systemd.SysUpdate.h"
#include "varlink-util.h"
#include "verbs.h"

static char *arg_definitions = NULL;
static bool arg_sync = true;
static uint64_t arg_instances_max = UINT64_MAX;
static sd_json_format_flags_t arg_json_format_flags = SD_JSON_FORMAT_OFF;
static PagerFlags arg_pager_flags = 0;
static bool arg_legend = true;
static char *arg_root = NULL;
static char *arg_image = NULL;
static bool arg_reboot = false;
static int arg_cleanup = -1;
static SelectMode arg_feature_select = SELECT_EXPLICIT;
static char *arg_component = NULL;
static SelectMode arg_component_select = SELECT_EXPLICIT;
static int arg_verify = -1;
static ImagePolicy *arg_image_policy = NULL;
static bool arg_offline = false;
static char *arg_transfer_source = NULL;
static bool arg_varlink = false;

STATIC_DESTRUCTOR_REGISTER(arg_definitions, freep);
STATIC_DESTRUCTOR_REGISTER(arg_root, freep);
STATIC_DESTRUCTOR_REGISTER(arg_image, freep);
STATIC_DESTRUCTOR_REGISTER(arg_component, freep);
STATIC_DESTRUCTOR_REGISTER(arg_image_policy, image_policy_freep);
STATIC_DESTRUCTOR_REGISTER(arg_transfer_source, freep);

#define CONTEXT_NULL                                              \
        (Context) {                                               \
                .component_enabled = true,                        \
                .sync = true,                                     \
                .instances_max = UINT64_MAX,                      \
                .verify = -1,                                     \
                .cleanup = -1,                                    \
                .installdb_fd = -EBADF,                           \
                .target_identifier.class = _TARGET_CLASS_INVALID, \
                .component_suggest = -1,                          \
        }

void context_done(Context *c) {
        assert(c);

        c->mounted_dir = umount_and_rmdir_and_free(c->mounted_dir);
        c->loop_device = loop_device_unref(c->loop_device);

        FOREACH_ARRAY(tr, c->transfers, c->n_transfers)
                transfer_free(*tr);
        c->transfers = mfree(c->transfers);
        c->n_transfers = 0;

        FOREACH_ARRAY(tr, c->disabled_transfers, c->n_disabled_transfers)
                transfer_free(*tr);
        c->disabled_transfers = mfree(c->disabled_transfers);
        c->n_disabled_transfers = 0;

        c->features = hashmap_free(c->features);

        FOREACH_ARRAY(us, c->update_sets, c->n_update_sets)
                update_set_free(*us);
        c->update_sets = mfree(c->update_sets);
        c->n_update_sets = 0;

        c->web_cache = hashmap_free(c->web_cache);

        c->installdb_fd = safe_close(c->installdb_fd);

        c->definitions = mfree(c->definitions);
        c->root = mfree(c->root);
        c->image = mfree(c->image);
        c->component = mfree(c->component);
        c->component_description = mfree(c->component_description);
        c->component_documentation = strv_free(c->component_documentation);
        c->image_policy = image_policy_free(c->image_policy);
        c->transfer_source = mfree(c->transfer_source);

        target_identifier_done(&c->target_identifier);
        condition_free_list(c->component_suggest_on);
}

static int context_from_cmdline(Context *ret) {
        assert(ret);

        _cleanup_(context_done) Context context = CONTEXT_NULL;

        context.instances_max = arg_instances_max;
        context.sync = arg_sync;
        context.reboot = arg_reboot;
        context.verify = arg_verify;
        context.offline = arg_offline;
        context.cleanup = arg_cleanup;
        context.component_select = arg_component_select;
        context.feature_select = arg_feature_select;

        if (strdup_to(&context.definitions, arg_definitions) < 0)
                return log_oom();

        if (strdup_to(&context.root, arg_root) < 0)
                return log_oom();

        if (strdup_to(&context.image, arg_image) < 0)
                return log_oom();

        if (strdup_to(&context.component, arg_component) < 0)
                return log_oom();

        if (strdup_to(&context.transfer_source, arg_transfer_source) < 0)
                return log_oom();

        if (arg_image_policy) {
                context.image_policy = image_policy_copy(arg_image_policy);
                if (!context.image_policy)
                        return log_oom();
        }

        *ret = TAKE_GENERIC(context, Context, CONTEXT_NULL);
        return 0;
}

static int context_from_base_with_component(const Context *base, const char *component, Context *ret) {
        assert(base);
        assert(component);
        assert(ret);

        /* Copies the specified context, but changes the component to the specified one */

        _cleanup_(context_done) Context context = CONTEXT_NULL;

        context.instances_max = base->instances_max;
        context.sync = base->sync;
        context.reboot = base->reboot;
        context.verify = base->verify;
        context.offline = base->offline;
        context.cleanup = base->cleanup;
        context.feature_select = base->feature_select;

        if (strdup_to(&context.root, base->root) < 0)
                return log_oom();

        if (strdup_to(&context.image, base->image) < 0)
                return log_oom();

        if (strdup_to(&context.transfer_source, base->transfer_source) < 0)
                return log_oom();

        if (base->image_policy) {
                context.image_policy = image_policy_copy(base->image_policy);
                if (!context.image_policy)
                        return log_oom();
        }

        if (strdup_to(&context.component, component) < 0)
                return log_oom();

        /* NB: we do not copy .loop_device/.mounted_dir here, since that's for lifetime tracking only, and
         * not needed for access (we only need to copy .root/.image) for that. Under the assumption that the
         * contexts initialized via context_from_base_with_component() have a shorter lifetime than the
         * contexts they are copied from we don't bother with lifetime tracking of the loopback device/mount
         * point here. */

        *ret = TAKE_GENERIC(context, Context, CONTEXT_NULL);
        return 0;
}

/* Stores any long-running server state which needs to persist between varlink calls, such as state for
 * pending polkit requests */
typedef struct Server {
        sd_bus *system_bus;
        Hashmap *polkit_registry;
} Server;

#define SERVER_NULL \
        (Server) { \
                /* all fields fine with being initialised to NULL */ \
        }

static void server_done(Server *s) {
        assert(s);

        s->polkit_registry = hashmap_free(s->polkit_registry);
        s->system_bus = sd_bus_flush_close_unref(s->system_bus);
}

static DEFINE_POINTER_ARRAY_FREE_FUNC(Transfer*, transfer_free);

static int read_features(
                Context *c,
                const char **dirs) {

        int r;

        assert(c);

        ConfFile **files = NULL;
        size_t n_files = 0;
        CLEANUP_ARRAY(files, n_files, conf_file_free_array);

        r = conf_files_list_strv_full(
                        ".feature",
                        c->root,
                        CONF_FILES_REGULAR|CONF_FILES_FILTER_MASKED|CONF_FILES_WARN,
                        dirs,
                        &files,
                        &n_files);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate sysupdate.d/*.feature definitions: %m");

        FOREACH_ARRAY(i, files, n_files) {
                ConfFile *e = *i;

                _cleanup_(feature_unrefp) Feature *f = feature_new();
                if (!f)
                        return log_oom();

                r = feature_read_definition(f, c->root, e->result, dirs);
                if (r < 0)
                        return r;

                r = hashmap_ensure_put(&c->features, &feature_hash_ops, f->id, f);
                if (r < 0)
                        return log_error_errno(r, "Failed to insert feature '%s' into map: %m", f->id);

                TAKE_PTR(f);
        }

        return 0;
}

static int read_transfers(
                Context *c,
                const char **dirs,
                const char *suffix,
                const char *node) {

        ConfFile **files = NULL;
        Transfer **transfers = NULL, **disabled = NULL;
        size_t n_files = 0, n_transfers = 0, n_disabled = 0;
        int r;

        CLEANUP_ARRAY(files, n_files, conf_file_free_array);
        CLEANUP_ARRAY(transfers, n_transfers, transfer_free_array);
        CLEANUP_ARRAY(disabled, n_disabled, transfer_free_array);

        assert(c);
        assert(dirs);
        assert(suffix);

        r = conf_files_list_strv_full(suffix, c->root,
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

                r = transfer_resolve_paths(t, c->root, node);
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

static int read_component(Context *c) {
        int r;

        assert(c);

        /* Read a component description file, but only if we actually operate on a component */
        if (c->definitions || !c->component)
                return 0;

        _cleanup_free_ char *j = strjoin("sysupdate.", c->component, ".component");
        if (!j)
                return log_oom();

        ConfigTableItem table[] = {
                { "Component", "Description",                config_parse_string,              0,                             &c->component_description   },
                { "Component", "Documentation",              config_parse_url_specifiers_many, 0,                             &c->component_documentation },
                { "Component", "Enabled",                    config_parse_bool,                0,                             &c->component_enabled       },
                { "Component", "Suggest",                    config_parse_tristate,            0,                             &c->component_suggest       },
                { "Component", "SuggestOnArchitecture",      config_parse_condition,           CONDITION_ARCHITECTURE,        &c->component_suggest_on    },
                { "Component", "SuggestOnFirmware",          config_parse_condition,           CONDITION_FIRMWARE,            &c->component_suggest_on    },
                { "Component", "SuggestOnVirtualization",    config_parse_condition,           CONDITION_VIRTUALIZATION,      &c->component_suggest_on    },
                { "Component", "SuggestOnHost",              config_parse_condition,           CONDITION_HOST,                &c->component_suggest_on    },
                { "Component", "SuggestOnFraction",          config_parse_condition,           CONDITION_FRACTION,            &c->component_suggest_on    },
                { "Component", "SuggestOnKernelCommandLine", config_parse_condition,           CONDITION_KERNEL_COMMAND_LINE, &c->component_suggest_on    },
                { "Component", "SuggestOnVersion",           config_parse_condition,           CONDITION_VERSION,             &c->component_suggest_on    },
                { "Component", "SuggestOnCredential",        config_parse_condition,           CONDITION_CREDENTIAL,          &c->component_suggest_on    },
                { "Component", "SuggestOnSecurity",          config_parse_condition,           CONDITION_SECURITY,            &c->component_suggest_on    },
                { "Component", "SuggestOnOSRelease",         config_parse_condition,           CONDITION_OS_RELEASE,          &c->component_suggest_on    },
                { "Component", "SuggestOnMachineTag",        config_parse_condition,           CONDITION_MACHINE_TAG,         &c->component_suggest_on    },
                {}
        };

        r = config_parse_standard_file_with_dropins_full(
                        c->root,
                        /* root_fd= */ -EBADF,
                        j,
                        "Component\0",
                        config_item_table_lookup, table,
                        CONFIG_PARSE_WARN,
                        /* userdata= */ (void *) c->root,
                        /* ret_stats_by_path= */ NULL,
                        /* ret_dropin_files= */ NULL);
        if (r < 0)
                return r;

        return 0;
}

typedef enum ReadDefinitionsFlags {
        READ_DEFINITIONS_REQUIRES_ENABLED_TRANSFERS = 1 << 0, /* fail unless there's at least one enabled transfer */
        READ_DEFINITIONS_REQUIRES_ANY_TRANSFERS     = 1 << 1, /* fail unless there's at least one transfer */
        READ_DEFINITIONS_REQUIRES_ENABLED_COMPONENT = 1 << 2, /* fail if component is disabled */
} ReadDefinitionsFlags;

static int context_read_definitions(Context *c, const char* node, ReadDefinitionsFlags flags) {
        _cleanup_strv_free_ char **dirs = NULL;
        int r;

        assert(c);

        if (c->definitions)
                dirs = strv_new(c->definitions);
        else if (c->component) {
                char **l = CONF_PATHS_STRV("");
                size_t i = 0;

                dirs = new0(char*, strv_length(l) + 1);
                if (!dirs)
                        return log_oom();

                STRV_FOREACH(dir, l) {
                        char *j;

                        j = strjoin(*dir, "sysupdate.", c->component, ".d");
                        if (!j)
                                return log_oom();

                        dirs[i++] = j;
                }
        } else
                dirs = strv_new(CONF_PATHS("sysupdate.d"));
        if (!dirs)
                return log_oom();

        r = read_component(c);
        if (r < 0)
                return r;

        r = read_features(c, (const char**) dirs);
        if (r < 0)
                return r;

        r = read_transfers(c, (const char**) dirs, ".transfer", node);
        if (r < 0)
                return r;

        if (c->n_transfers + c->n_disabled_transfers == 0) {
                /* Backwards-compat: If no .transfer defs are found, fall back to trying .conf! */
                r = read_transfers(c, (const char**) dirs, ".conf", node);
                if (r < 0)
                        return r;

                if (c->n_transfers + c->n_disabled_transfers > 0)
                        log_warning("As of v257, transfer definitions should have the '.transfer' extension.");
        }

        if (FLAGS_SET(flags, READ_DEFINITIONS_REQUIRES_ANY_TRANSFERS) &&
            c->n_transfers + (FLAGS_SET(flags, READ_DEFINITIONS_REQUIRES_ENABLED_TRANSFERS) ? 0 : c->n_disabled_transfers) == 0) {
                if (c->component)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOENT),
                                               "No transfer definitions for component '%s' found.",
                                               c->component);

                return log_error_errno(SYNTHETIC_ERRNO(ENOENT),
                                       "No transfer definitions found.");
        }

        if (FLAGS_SET(flags, READ_DEFINITIONS_REQUIRES_ENABLED_COMPONENT) && !c->component_enabled)
                return log_error_errno(SYNTHETIC_ERRNO(EHOSTDOWN), "Component is disabled.");

        return 0;
}

static int context_load_installed_instances(Context *c) {
        int r;

        assert(c);

        log_debug("Discovering installed instances%s", glyph(GLYPH_ELLIPSIS));

        FOREACH_ARRAY(tr, c->transfers, c->n_transfers) {
                Transfer *t = *tr;

                r = resource_load_instances(
                                &t->target,
                                c->verify >= 0 ? c->verify : t->verify,
                                &c->web_cache);
                if (r < 0)
                        return r;
        }

        FOREACH_ARRAY(tr, c->disabled_transfers, c->n_disabled_transfers) {
                Transfer *t = *tr;

                r = resource_load_instances(
                                &t->target,
                                c->verify >= 0 ? c->verify : t->verify,
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
                                c->verify >= 0 ? c->verify : t->verify,
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

                                if (cursor && strverscmp_improved(i->metadata.version, cursor) <= 0)
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
                                if (!match && !(extra_flags & (UPDATE_PARTIAL|UPDATE_PENDING)))
                                        /* When we're looking for installed versions, let's be robust and treat
                                         * an incomplete installation as an installation. Otherwise, there are
                                         * situations that can lead to sysupdate wiping the currently booted OS.
                                         * See https://github.com/systemd/systemd/issues/33339 */
                                        extra_flags |= UPDATE_INCOMPLETE;
                        }

                        cursor_instances[k] = match;

                        if (t->min_version && strverscmp_improved(t->min_version, cursor) > 0)
                                extra_flags |= UPDATE_OBSOLETE;

                        if (strv_contains(t->protected_versions, cursor))
                                extra_flags |= UPDATE_PROTECTED;

                        /* Partial or pending updates by definition are not incomplete, they’re
                         * partial/pending instead. While an individual Instance cannot be both partial and
                         * pending, an UpdateSet as a whole can contain both partial and pending instances. */
                        assert(!match || !(match->is_partial && match->is_pending));

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

        /* Newest installed is still pending or partial and no candidate is set? Then it becomes the candidate. */
        if (c->newest_installed &&
            (c->newest_installed->flags & (UPDATE_PENDING|UPDATE_PARTIAL)) &&
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

        if (!c->offline) {
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
                        assert(us->flags & (UPDATE_INCOMPLETE|UPDATE_PARTIAL|UPDATE_PENDING));
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

typedef enum ProcessImageFlags {
        PROCESS_IMAGE_READ_ONLY = 1 << 0,
} ProcessImageFlags;

static int context_process_image(
                Context *c,
                ProcessImageFlags flags) {

        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(umount_and_rmdir_and_freep) char *mounted_dir = NULL;
        int r;

        assert(c);

        if (c->root || !c->image) /* Idempotent or nothing to do */
                return 0;

        assert(!c->mounted_dir);
        assert(!c->loop_device);

        r = mount_image_privately_interactively(
                        c->image,
                        c->image_policy,
                        (FLAGS_SET(flags, PROCESS_IMAGE_READ_ONLY) ? DISSECT_IMAGE_READ_ONLY : 0) |
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

        c->root = strdup(mounted_dir);
        if (!c->root)
                return log_oom();

        c->mounted_dir = TAKE_PTR(mounted_dir);
        c->loop_device = TAKE_PTR(loop_device);

        return 0;
}

static int context_list_components(Context *context, char ***ret_component_names, bool *ret_has_default_component);

static int context_load_offline(
                Context *context,
                ProcessImageFlags process_image_flags,
                ReadDefinitionsFlags read_definitions_flags) {
        int r;

        assert(context);

        /* Sets up a context object and initializes everything we can initialize offline, i.e. without
         * checking on the update source (i.e. the Internet) what versions are available */

        r = context_process_image(context, process_image_flags);
        if (r < 0)
                return r;

        r = context_read_definitions(context, context->loop_device ? context->loop_device->node : NULL, read_definitions_flags);
        if (r < 0)
                return r;

        r = context_load_installed_instances(context);
        if (r < 0)
                return r;

        return 0;
}

static int context_load_online(
                Context *context,
                ProcessImageFlags process_image_flags,
                ReadDefinitionsFlags read_definitions_flags) {

        int r;

        assert(context);

        /* Like context_load_offline(), but also communicates with the update source looking for new
         * versions (as long as --offline is not specified on the command line). */

        r = context_load_offline(
                        context,
                        process_image_flags,
                        read_definitions_flags);
        if (r < 0)
                return r;

        if (!context->offline) {
                r = context_load_available_instances(context);
                if (r < 0)
                        return r;
        }

        r = context_discover_update_sets(context);
        if (r < 0)
                return r;

        return 0;
}

static bool image_type_can_sysupdate(ImageType image_type) {
        /* systemd-sysupdate doesn't support mstack images yet */
        return IN_SET(image_type, IMAGE_DIRECTORY, IMAGE_SUBVOLUME, IMAGE_RAW, IMAGE_BLOCK);
}

static int context_load_paths_from_image(Context *context, Image *image) {
        assert(context);
        assert(image);

        assert(!context->root);
        assert(!context->image);

        switch (image->type) {
        case IMAGE_DIRECTORY:
        case IMAGE_SUBVOLUME:
                context->root = strdup(image->path);
                if (!context->root)
                        return log_oom();
                return 0;
        case IMAGE_RAW:
        case IMAGE_BLOCK:
                context->image = strdup(image->path);
                if (!context->image)
                        return log_oom();
                return 0;
        default:
                assert_not_reached();
        }
}

static void target_identifier_hash_func(const TargetIdentifier *t, struct siphash *state) {
        assert(t);

        siphash24_compress_typesafe(t->class, state);
        siphash24_compress_string(t->name, state);
}

static int target_identifier_compare_func(const TargetIdentifier *x, const TargetIdentifier *y) {
        int r;

        assert(x);
        assert(y);

        r = CMP(x->class, y->class);
        if (r != 0)
                return r;

        return strcmp(x->name, y->name);
}

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(target_identifier_hash_ops,
                                              TargetIdentifier, target_identifier_hash_func, target_identifier_compare_func,
                                              TargetIdentifier, target_identifier_free);

static int enumerate_image_class(RuntimeScope runtime_scope, TargetClass class, Set **targets) {
        _cleanup_hashmap_free_ Hashmap *images = NULL;
        Image *image;
        int r;

        r = image_discover(runtime_scope, (ImageClass) class, NULL, &images);
        if (r < 0)
                return r;

        HASHMAP_FOREACH(image, images) {
                _cleanup_(target_identifier_freep) TargetIdentifier *t = NULL;
                bool have = false;
                _cleanup_(context_done) Context image_context = CONTEXT_NULL;

                if (image_is_host(image))
                        continue; /* We already enroll the host ourselves */

                if (!image_type_can_sysupdate(image->type))
                        continue;

                r = context_load_paths_from_image(&image_context, image);
                if (r < 0)
                        return r;

                /* Load the components in a separate Context specific to the given Image before
                 * committing to loading that state to the main Context. */
                r = context_load_offline(
                                &image_context,
                                PROCESS_IMAGE_READ_ONLY,
                                /* read_definitions_flags= */ 0);
                if (r < 0)
                        return r;

                r = context_list_components(&image_context, /* ret_component_names= */ NULL, &have);
                if (r < 0)
                        return r;
                if (!have) {
                        log_debug("Skipping %s because it has no default component", image->path);
                        continue;
                }

                r = target_identifier_new(class, image->name, &t);
                if (r < 0)
                        return r;

                r = set_ensure_consume(targets, &target_identifier_hash_ops, TAKE_PTR(t));
                if (r < 0)
                        return r;
        }

        return 0;
}

static int context_enumerate_components(Context *context, Set **targets) {
        _cleanup_strv_free_ char **component_names = NULL;
        bool have_default_component;
        int r;

        assert(context);

        r = context_list_components(context, &component_names, &have_default_component);
        if (r < 0)
                return r;

        if (have_default_component) {
                _cleanup_(target_identifier_freep) TargetIdentifier *t = NULL;

                r = target_identifier_new(TARGET_HOST, "host", &t);
                if (r < 0)
                        return r;

                r = set_ensure_consume(targets, &target_identifier_hash_ops, TAKE_PTR(t));
                if (r < 0)
                        return r;
        }

        STRV_FOREACH(component, component_names) {
                _cleanup_(target_identifier_freep) TargetIdentifier *t = NULL;

                r = target_identifier_new(TARGET_COMPONENT, *component, &t);
                if (r < 0)
                        return r;

                r = set_ensure_consume(targets, &target_identifier_hash_ops, TAKE_PTR(t));
                if (r < 0)
                        return r;
        }

        return 0;
}

static int context_enumerate_targets(Context *context, Set **targets) {
        static const TargetClass discoverable_classes[] = {
                TARGET_MACHINE,
                TARGET_PORTABLE,
                TARGET_SYSEXT,
                TARGET_CONFEXT,
        };
        int r;

        assert(context);

        FOREACH_ARRAY(class, discoverable_classes, ELEMENTSOF(discoverable_classes)) {
                r = enumerate_image_class(RUNTIME_SCOPE_SYSTEM, *class, targets);
                if (r < 0)
                        return r;
        }

        r = context_enumerate_components(context, targets);
        if (r < 0)
                return r;

        return 0;
}

static int context_load_paths_from_target(Context *context) {
        int r;

        assert(context);
        assert(context->target_identifier.class != _TARGET_CLASS_INVALID);

        /* These shouldn’t have been set up some other way first */
        assert(!context->component);
        assert(!context->root);
        assert(!context->image);

        switch (context->target_identifier.class) {
        case TARGET_MACHINE:
        case TARGET_PORTABLE:
        case TARGET_SYSEXT:
        case TARGET_CONFEXT: {
                _cleanup_hashmap_free_ Hashmap *images = NULL;
                Image *image, *selected_image = NULL;

                /* These are all image-based target classes, so first find the corresponding image. */
                r = image_discover(RUNTIME_SCOPE_SYSTEM, (ImageClass) context->target_identifier.class, NULL, &images);
                if (r < 0)
                        return r;

                HASHMAP_FOREACH(image, images) {
                        bool have = false;
                        _cleanup_(context_done) Context image_context = CONTEXT_NULL;

                        if (image_is_host(image))
                                continue; /* We already enroll the host ourselves */

                        if (!image_type_can_sysupdate(image->type))
                                continue;

                        if (!streq(image->name, context->target_identifier.name))
                                continue;

                        r = context_load_paths_from_image(&image_context, image);
                        if (r < 0)
                                return r;

                        /* Load the components in a separate Context specific to the given Image before
                         * committing to loading that state to the main Context. */
                        r = context_load_offline(&image_context, 0, 0);
                        if (r < 0)
                                return r;

                        r = context_list_components(&image_context, /* ret_component_names= */ NULL, &have);
                        if (r < 0)
                                return r;
                        if (!have) {
                                log_debug("Skipping %s because it has no default component", image->path);
                                continue;
                        }

                        /* This is the match we were looking for */
                        selected_image = image;
                        break;
                }

                if (!selected_image)
                        return -ENOENT;

                r = context_load_paths_from_image(context, selected_image);
                if (r < 0)
                        return r;

                break;
        }
        case TARGET_HOST:
                /* No additional setup needed */
                break;
        case TARGET_COMPONENT: {
                _cleanup_strv_free_ char **component_names = NULL;

                r = context_list_components(context, &component_names, /* ret_has_default_component= */ NULL);
                if (r < 0)
                        return r;

                if (!strv_contains(component_names, context->target_identifier.name))
                        return -ENOENT;

                context->component = strdup(context->target_identifier.name);
                if (!context->component)
                        return log_oom();
                break;
        }
        default:
                assert_not_reached();
        }

        return 0;
}

/* Load a Context to point to the target given by the TargetIdentifier. The TargetIdentifier will have been
 * syntactically validated by dispatch_target_identifier(), but might still point to components which don’t
 * exist, images which the user isn’t privileged to access, etc. This function validates the TargetIdentifier
 * against an enumerated list of known targets, which are safe to update without additional permissions. */
static int context_load_online_from_target(
                Context *context,
                ProcessImageFlags process_image_flags,
                ReadDefinitionsFlags read_definitions_flags) {
        int r;

        assert(context);
        assert(context->target_identifier.class != _TARGET_CLASS_INVALID);

        r = context_load_paths_from_target(context);
        if (r < 0)
                return r;

        return context_load_online(context, process_image_flags, read_definitions_flags);
}

static int context_load_offline_from_target(
                Context *context,
                ProcessImageFlags process_image_flags,
                ReadDefinitionsFlags read_definitions_flags) {
        int r;

        assert(context);
        assert(context->target_identifier.class != _TARGET_CLASS_INVALID);

        r = context_load_paths_from_target(context);
        if (r < 0)
                return r;

        return context_load_offline(context, process_image_flags, read_definitions_flags);
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
                return log_error_errno(SYNTHETIC_ERRNO(EUCLEAN), "Selected update '%s' is already acquired and partially installed. Vacuum it to try installing again.", us->version);
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

        _cleanup_free_ InstanceMetadata *metadata = new0(InstanceMetadata, c->n_transfers);
        if (!metadata)
                return log_oom();

        /* Compute up the temporary paths before vacuuming so we don't vacuum anything if we fail to compute
         * any paths because of failed validations (e.g. exceeding the gpt partition label size). */
        for (size_t i = 0; i < c->n_transfers; i++) {
                Instance *inst = us->instances[i];
                Transfer *t = c->transfers[i];

                assert(inst);

                r = transfer_compute_temporary_paths(t, inst, metadata + i);
                if (r < 0)
                        return r;
        }

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

        if (c->sync)
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

                r = transfer_acquire_instance(t, inst, metadata + i, context_on_acquire_progress, c);
                if (r < 0)
                        return r;
        }

        if (c->sync)
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

static int notify_subscribers_reply(
                sd_varlink *link,
                sd_json_variant *reply,
                const char *error_id,
                sd_varlink_reply_flags_t flags,
                void *userdata) {

        assert(link);

        if (error_id)
                log_warning("Notification subscriber '%s' returned error, ignoring: %s",
                            strna(sd_varlink_get_description(link)), error_id);

        return 0;
}

static int context_notify_subscribers(Context *c, UpdateSet *us) {
        int r;

        assert(c);

        /* 'us' is NULL when we are forced to notify even though no update was applied (via
         * SYSTEMD_SYSUPDATE_FORCE_NOTIFY=1). In that case we send neither a version nor a resource list. */

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *resources = NULL;
        if (us)
                for (size_t i = 0; i < c->n_transfers; i++) {
                        Instance *inst = us->instances[i];
                        Transfer *t = c->transfers[i];

                        if (inst->resource == &t->target &&
                            !inst->is_pending)
                                continue;

                        /* Report where the resource was installed *to* (not the source it came from): the
                         * final on-disk path for filesystem targets, the partition device node for partition
                         * targets. */
                        const char *target_path =
                                RESOURCE_IS_FILESYSTEM(t->target.type) ? t->final_path :
                                t->target.type == RESOURCE_PARTITION ? t->partition_info.device :
                                NULL;

                        r = sd_json_variant_append_arraybo(
                                        &resources,
                                        SD_JSON_BUILD_PAIR_STRING("transfer", t->id),
                                        SD_JSON_BUILD_PAIR_CONDITION(!!target_path, "path", SD_JSON_BUILD_STRING(target_path)));
                        if (r < 0)
                                return log_warning_errno(r, "Failed to build sysupdate notify resources list, skipping notification: %m");
                }

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *params = NULL;
        r = sd_json_buildo(
                        &params,
                        SD_JSON_BUILD_PAIR_CONDITION(!!c->component, "component", SD_JSON_BUILD_STRING(c->component)),
                        SD_JSON_BUILD_PAIR_CONDITION(!!us, "version", SD_JSON_BUILD_STRING(us ? us->version : NULL)),
                        SD_JSON_BUILD_PAIR_CONDITION(!!resources, "resources", SD_JSON_BUILD_VARIANT(resources)));
        if (r < 0)
                return log_warning_errno(r, "Failed to build sysupdate notify parameters, skipping notification: %m");

        ssize_t n = varlink_execute_directory(
                        VARLINK_DIR_SYSUPDATE_NOTIFY_HOOK,
                        "io.systemd.SysUpdate.Notify.OnCompletedUpdate",
                        params,
                        /* more= */ false,
                        /* timeout_usec= */ 5 * USEC_PER_MINUTE,
                        notify_subscribers_reply,
                        /* userdata= */ NULL);
        if (n < 0)
                log_debug_errno(n, "Failed to dispatch sysupdate notification to %s, ignoring: %m",
                                VARLINK_DIR_SYSUPDATE_NOTIFY_HOOK);
        else if (n > 0)
                log_debug("Dispatched sysupdate notification to %zi subscribers in %s.", n, VARLINK_DIR_SYSUPDATE_NOTIFY_HOOK);

        return 0;
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
                          "READY=1\n"
                          "X_SYSUPDATE_VERSION=%s\n"
                          "STATUS=Installing '%s'.", us->version, us->version);

        for (size_t i = 0; i < c->n_transfers; i++) {
                Instance *inst = us->instances[i];
                Transfer *t = c->transfers[i];

                if (inst->resource == &t->target &&
                    !inst->is_pending)
                        continue;

                r = transfer_install_instance(t, inst, c->root);
                if (r < 0)
                        return r;
        }

        log_info("%s Successfully installed update '%s'.", glyph(GLYPH_SPARKLES), us->version);

        if (!c->root)
                (void) context_notify_subscribers(c, us);

        (void) sd_notifyf(/* unset_environment= */ false,
                          "STATUS=Installed '%s'.", us->version);

        if (ret_applied)
                *ret_applied = us;

        return 1;
}

static int context_get_transfers_for_feature(Context *context, const char *feature_id, char ***ret_transfers) {
        int r;

        assert(context);
        assert(feature_id);

        FOREACH_ARRAY(tr, context->transfers, context->n_transfers) {
                Transfer *t = *tr;

                if (!strv_contains(t->features, feature_id) && !strv_contains(t->requisite_features, feature_id))
                        continue;

                r = strv_extend(ret_transfers, t->id);
                if (r < 0)
                        return log_oom();
        }

        FOREACH_ARRAY(tr, context->disabled_transfers, context->n_disabled_transfers) {
                Transfer *t = *tr;

                if (!strv_contains(t->features, feature_id) && !strv_contains(t->requisite_features, feature_id))
                        continue;

                r = strv_extend(ret_transfers, t->id);
                if (r < 0)
                        return log_oom();
        }

        return 0;
}

static JSON_DISPATCH_ENUM_DEFINE(dispatch_target_class, TargetClass, target_class_from_string);

static int dispatch_target_identifier(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        TargetIdentifier *t = ASSERT_PTR(userdata);
        static const sd_json_dispatch_field dispatch[] = {
                { "class", SD_JSON_VARIANT_STRING, dispatch_target_class,   voffsetof(*t, class), SD_JSON_MANDATORY },
                { "name",  SD_JSON_VARIANT_STRING, sd_json_dispatch_string, voffsetof(*t, name),  SD_JSON_NULLABLE  },
                {}
        };
        int r;

        r = sd_json_dispatch(variant, dispatch, flags, t);
        if (r < 0)
                return r;

        /* Name is mandatory unless class is `host` */
        if ((t->class == TARGET_HOST) != (!t->name))
                return json_log(variant, flags, SYNTHETIC_ERRNO(ENXIO), "Target name does not match class.");

        if (t->class == TARGET_COMPONENT && !component_name_valid(t->name))
                        return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "Component name invalid: %s", t->name);

        return 0;
}

static int verify_polkit(Context *context, sd_varlink *link, const char *action, const char **details) {
        int r;
        Server *s = ASSERT_PTR(sd_varlink_get_userdata(ASSERT_PTR(link)));

        assert(context);

        if (!s->system_bus) {
                r = sd_bus_open_system_with_description(&s->system_bus, "sysupdate-system");
                if (r < 0)
                        return log_error_errno(r, "Failed to get system bus connection: %m");

                r = sd_bus_attach_event(s->system_bus, sd_varlink_get_event(link), SD_EVENT_PRIORITY_NORMAL);
                if (r < 0)
                        return log_error_errno(r, "Failed to attach system bus to event loop: %m");
        }

        return varlink_verify_polkit_async(link,
                        s->system_bus,
                        action,
                        details,
                        &s->polkit_registry);
}

VERB(verb_list, "list", "[VERSION]", VERB_ANY, 2, VERB_DEFAULT,
     "Show installed and available versions");
static int verb_list(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(context_done) Context context = CONTEXT_NULL;
        _cleanup_strv_free_ char **appstream_urls = NULL;
        const char *version;
        int r;

        assert(argc <= 2);
        version = argc >= 2 ? argv[1] : NULL;

        r = context_from_cmdline(&context);
        if (r < 0)
                return r;

        if (context.feature_select != SELECT_EXPLICIT)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--feature-all/--feature-suggested is not supported for '%s'.", argv[0]);
        if (context.component_select != SELECT_EXPLICIT)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "--component-all/--component-suggested currently not supported for '%s'.", argv[0]);

        r = context_load_online(
                        &context,
                        PROCESS_IMAGE_READ_ONLY,
                        READ_DEFINITIONS_REQUIRES_ENABLED_TRANSFERS|
                        READ_DEFINITIONS_REQUIRES_ANY_TRANSFERS);
        if (r < 0)
                return r;

        if (version)
                return context_show_version(&context, version);
        else if (!sd_json_format_enabled(arg_json_format_flags))
                return context_show_table(&context);
        else {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *json = NULL;
                _cleanup_strv_free_ char **versions = NULL;
                const char *current = NULL;
                bool current_is_pending = false;

                FOREACH_ARRAY(update_set, context.update_sets, context.n_update_sets) {
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

                FOREACH_ARRAY(tr, context.transfers, context.n_transfers)
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

VERB(verb_features, "features", "[FEATURE]", VERB_ANY, 2, 0,
     "Show optional features");
static int verb_features(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(context_done) Context context = CONTEXT_NULL;
        _cleanup_(table_unrefp) Table *table = NULL;
        const char *feature_id;
        Feature *f;
        int r;

        assert(argc <= 2);
        feature_id = argc >= 2 ? argv[1] : NULL;

        r = context_from_cmdline(&context);
        if (r < 0)
                return r;

        if (context.feature_select != SELECT_EXPLICIT)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--feature-all/--feature-suggested is not supported for '%s'.", argv[0]);
        if (context.component_select != SELECT_EXPLICIT)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "--component-all/--component-suggested currently not supported for '%s'.", argv[0]);

        r = context_load_offline(
                        &context,
                        PROCESS_IMAGE_READ_ONLY,
                        READ_DEFINITIONS_REQUIRES_ANY_TRANSFERS);
        if (r < 0)
                return r;

        if (feature_id) {
                _cleanup_strv_free_ char **transfers = NULL;

                f = hashmap_get(context.features, feature_id);
                if (!f)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOENT),
                                               "Optional feature not found: %s",
                                               feature_id);

                table = table_new_vertical();
                if (!table)
                        return log_oom();

                r = context_get_transfers_for_feature(&context, f->id, &transfers);
                if (r < 0)
                        return r;

                r = table_add_many(table,
                                   TABLE_FIELD, "Name",
                                   TABLE_STRING, f->id,
                                   TABLE_FIELD, "Enabled",
                                   TABLE_BOOLEAN, f->enabled);
                if (r < 0)
                        return table_log_add_error(r);

                r = feature_is_suggested(f);
                if (r < 0) {
                        errno = -r; /* Let's make %m below show this error */
                        _cleanup_free_ char *k = asprintf_safe("error (%m)");
                        r = table_add_many(table,
                                           TABLE_FIELD, "Suggested",
                                           TABLE_STRING, k);
                } else
                        r = table_add_many(table,
                                           TABLE_FIELD, "Suggested",
                                           TABLE_BOOLEAN, r);
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
                table = table_new("enabled", "suggested", "feature", "description", "documentation");
                if (!table)
                        return log_oom();

                table_set_ersatz_string(table, TABLE_ERSATZ_DASH);

                HASHMAP_FOREACH(f, context.features) {
                        r = table_add_many(table,
                                           TABLE_BOOLEAN_CHECKMARK, f->enabled,
                                           TABLE_SET_COLOR, ansi_highlight_green_red(f->enabled));
                        if (r < 0)
                                return table_log_add_error(r);

                        r = feature_is_suggested(f);
                        if (r < 0)
                                r = table_add_many(table, TABLE_EMPTY);
                        else
                                r = table_add_many(table, TABLE_BOOLEAN_CHECKMARK, r);
                        if (r < 0)
                                return table_log_add_error(r);

                        r = table_add_many(table,
                                           TABLE_STRING, f->id,
                                           TABLE_STRING, f->description,
                                           TABLE_STRING, f->documentation,
                                           TABLE_SET_URL, f->documentation);
                        if (r < 0)
                                return table_log_add_error(r);
                }

                r = table_print_with_pager(table, arg_json_format_flags, arg_pager_flags, arg_legend);
                if (r < 0)
                        return r;

                if (arg_legend) {
                        if (table_isempty(table))
                                log_info("No features.");
                        else
                                printf("\n%zu features listed.\n", table_get_rows(table) - 1);
                }
        } else {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *json = NULL;
                _cleanup_strv_free_ char **features = NULL;

                HASHMAP_FOREACH(f, context.features) {
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

static int make_dropin_dir(Context *c, char **ret) {
        _cleanup_free_ char *dir = NULL;

        assert(c);
        assert(ret);

        /* Returns the (writable) directory where feature definitions live, so that we can drop our
         * 'Enabled=' override right next to them. This mirrors the directory logic in
         * context_read_definitions(), but settles on a single writable location below /etc. */

        if (c->definitions)
                dir = strdup(c->definitions); /* --root= is not supported for this for now */
        else if (c->component) {
                _cleanup_free_ char *n = strjoin("sysupdate.", c->component, ".d");
                if (!n)
                        return log_oom();

                dir = path_join(c->root, SYSCONF_DIR, n);
        } else
                dir = path_join(c->root, SYSCONF_DIR "/sysupdate.d");
        if (!dir)
                return log_oom();

        *ret = TAKE_PTR(dir);
        return 0;
}

static const char *context_component_display(const Context *c) {
        assert(c);

        return c->component ?: "<default>";
}

static int context_enable_feature(
                Context *c,
                const char *argv0,
                bool enable,
                char **features) {

        int r;

        assert(c);
        assert(argv0);

        _cleanup_free_ char **l = NULL;
        switch (c->feature_select) {

        case SELECT_EXPLICIT:
                break;

        case SELECT_ALL: {
                assert(!features);

                Feature *f;
                HASHMAP_FOREACH(f, c->features)
                        if (strv_push(&l, f->id) < 0)
                                return log_oom();

                features = l;
                break;
        }

        case SELECT_SUGGESTED: {
                assert(!features);

                Feature *f;
                HASHMAP_FOREACH(f, c->features) {
                        r = feature_is_suggested(f);
                        if (r < 0)
                                return log_error_errno(r, "Failed to determine if feature '%s' of component '%s' shall be enabled: %m", f->id, context_component_display(c));
                        if (!!r != !!enable) {
                                log_debug("Skipping feature '%s' of component '%s'.", f->id, context_component_display(c));
                                continue;
                        }

                        log_info("%s feature '%s' of component '%s'.", enable ? "Enabling" : "Disabling", f->id, context_component_display(c));

                        if (strv_push(&l, f->id) < 0)
                                return log_oom();
                }

                features = l;
                break;
        }

        default:
                assert_not_reached();
        }

        if (strv_isempty(features)) {
                log_debug("No features selected.");
                return 0;
        }

        _cleanup_free_ char *dropin_dir = NULL;
        r = make_dropin_dir(c, &dropin_dir);
        if (r < 0)
                return r;

        int ret = 0;
        STRV_FOREACH(name, features) {
                if (!hashmap_contains(c->features, *name)) {
                        RET_GATHER(ret, log_error_errno(SYNTHETIC_ERRNO(ENOENT), "Optional feature not found in component '%s': %s", context_component_display(c), *name));
                        continue;
                }

                _cleanup_free_ char *fname = strjoin(*name, ".feature");
                if (!fname)
                        return log_oom();

                /* We assume that no sysadmin will name their config 50-systemd-sysupdate-enabled.conf */
                r = write_drop_in_format(
                                dropin_dir,
                                fname,
                                50,
                                "systemd-sysupdate-enabled",
                                "# Generated via 'systemd-sysupdate %s'\n\n"
                                "[Feature]\n"
                                "Enabled=%s\n",
                                argv0,
                                yes_no(enable));
                if (r < 0) {
                        RET_GATHER(ret, log_error_errno(r, "Failed to write drop-in for feature '%s': %m", *name));
                        continue;
                }

                log_info("Feature '%s' %s.", *name, enabled_disabled(enable));
        }

        return ret;
}

VERB(verb_enable_feature, "enable-feature", "FEATURE…", 1, VERB_ANY, 0,
     "Enable optional feature");
VERB(verb_enable_feature, "disable-feature", "FEATURE…", 1, VERB_ANY, 0,
     "Disable optional feature");
static int verb_enable_feature(int argc, char *argv[], uintptr_t _data, void *userdata) {
        bool enable = streq(argv[0], "enable-feature");
        int r;

        _cleanup_(context_done) Context context = CONTEXT_NULL;
        r = context_from_cmdline(&context);
        if (r < 0)
                return r;

        if (!IN_SET(context.component_select, SELECT_EXPLICIT, SELECT_ALL))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--component-suggested is not supported for '%s'.", argv[0]);
        if (context.definitions)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "The --definitions= switch may not be combined with '%s'.", argv[0]);

        char **features;
        if (argc > 1 && context.feature_select == SELECT_EXPLICIT) {
                features = strv_skip(argv, 1);

                STRV_FOREACH(name, features)
                        if (!feature_name_valid(*name))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Feature name invalid: %s", *name);

        } else if (argc <= 1 && context.feature_select != SELECT_EXPLICIT)
                features = NULL;
        else
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Either specify features as positional parameter or via --feature-all/--feature-suggested, not both.");

        r = context_load_offline(
                        &context,
                        /* process_image_flags= */ 0,
                        /* read_definitions_flags= */ 0);
        if (r < 0)
                return r;

        switch (context.component_select) {

        case SELECT_EXPLICIT:
                return context_enable_feature(&context, argv[0], enable, features);

        case SELECT_ALL: {
                _cleanup_strv_free_ char **component_names = NULL;
                bool has_default_component;
                r = context_list_components(&context, &component_names, &has_default_component);
                if (r < 0)
                        return r;

                if (strv_isempty(component_names) && !has_default_component) {
                        log_debug("No components selected.");
                        return 0;
                }

                int ret = 0;
                if (has_default_component)
                        RET_GATHER(ret, context_enable_feature(&context, argv[0], enable, features));

                STRV_FOREACH(name, component_names) {
                        _cleanup_(context_done) Context cc = CONTEXT_NULL;

                        r = context_from_base_with_component(&context, *name, &cc);
                        if (r < 0) {
                                RET_GATHER(ret, r);
                                continue;
                        }

                        r = context_load_offline(
                                        &cc,
                                        /* process_image_flags= */ 0,
                                        /* read_definitions_flags= */ 0);
                        if (r < 0) {
                                RET_GATHER(ret, r);
                                continue;
                        }

                        RET_GATHER(ret, context_enable_feature(&cc, argv[0], enable, features));
                }

                return ret;
        }

        default:
                assert_not_reached();
        }
}

static int feature_to_json(Context *context, const Feature *f, sd_json_variant **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_strv_free_ char **transfers = NULL;
        const char *documentation_strv[2] = { NULL, };
        int r;

        assert(context);
        assert(f);
        assert(ret);

        r = context_get_transfers_for_feature(context, f->id, &transfers);
        if (r < 0)
                return r;

        /* FIXME: Long term we’d like to support an array of documentation, but currently the D-Bus interface
         * doesn’t support that and neither do the internals of sysupdate. So just expose 0 or 1 URLs for now. */
        documentation_strv[0] = f->documentation;

        r = sd_json_variant_merge_objectbo(
                        &v,
                        SD_JSON_BUILD_PAIR_STRING("id", f->id),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("description", f->description),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("documentation", (char **) documentation_strv),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("appstream", f->appstream),
                        SD_JSON_BUILD_PAIR_BOOLEAN("isEnabled", f->enabled),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("transfers", transfers));
        if (r < 0)
                return log_oom();

        *ret = TAKE_PTR(v);
        return 1;
}

static int vl_method_list_features(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        _cleanup_(context_done) Context context = CONTEXT_NULL;
        Feature *f;
        int r;

        assert(link);

        static const sd_json_dispatch_field dispatch_table[] = {
                { "target", SD_JSON_VARIANT_OBJECT, dispatch_target_identifier, voffsetof(context, target_identifier), SD_JSON_MANDATORY },
                {},
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &context);
        if (r != 0)
                return r;

        /* Listing features doesn’t require a polkit check */

        if (getenv_bool("SYSTEMD_SYSUPDATE_NO_VERIFY") > 0)
                context.verify = 0;

        /* ListFeatures is always offline */
        context.offline = true;

        r = context_load_offline_from_target(
                        &context,
                        PROCESS_IMAGE_READ_ONLY,
                        READ_DEFINITIONS_REQUIRES_ANY_TRANSFERS);
        if (r == -ENOENT)
                return sd_varlink_error(link, "io.systemd.SysUpdate.NoSuchTarget", NULL);
        if (r < 0)
                return r;

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *l = NULL;

        HASHMAP_FOREACH(f, context.features) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

                r = feature_to_json(&context, f, &v);
                if (r < 0)
                        return r;

                r = sd_json_variant_append_array(&l, v);
                if (r < 0)
                        return r;
        }

        if (!l) {
                r = sd_json_variant_new_array(&l, NULL, 0);
                if (r < 0)
                        return r;
        }

        return sd_varlink_replybo(link,
                        SD_JSON_BUILD_PAIR_VARIANT("features", l));
}

VERB_NOARG(verb_check_new, "check-new",
           "Check if there's a new version available");
static int verb_check_new(int argc, char *argv[], uintptr_t _data, void *userdata) {
        int r;

        assert(argc <= 1);

        _cleanup_(context_done) Context context = CONTEXT_NULL;
        r = context_from_cmdline(&context);
        if (r < 0)
                return r;

        if (context.feature_select != SELECT_EXPLICIT)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--feature-all/--feature-suggested is not supported for '%s'.", argv[0]);
        if (context.component_select != SELECT_EXPLICIT)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "--component-all/--component-suggested currently not supported for '%s'.", argv[0]);

        r = context_load_online(
                        &context,
                        PROCESS_IMAGE_READ_ONLY,
                        READ_DEFINITIONS_REQUIRES_ENABLED_TRANSFERS|
                        READ_DEFINITIONS_REQUIRES_ANY_TRANSFERS);
        if (r < 0)
                return r;

        if (!sd_json_format_enabled(arg_json_format_flags)) {
                if (!context.candidate) {
                        log_debug("No candidate found.");
                        return EXIT_FAILURE;
                }

                puts(context.candidate->version);
        } else {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *json = NULL;

                if (context.candidate)
                        r = sd_json_buildo(&json, SD_JSON_BUILD_PAIR_STRING("available", context.candidate->version));
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

static int vl_method_check_new(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        _cleanup_(context_done) Context context = CONTEXT_NULL;
        int r;

        assert(link);

        static const sd_json_dispatch_field dispatch_table[] = {
                { "target", SD_JSON_VARIANT_OBJECT, dispatch_target_identifier, voffsetof(context, target_identifier), SD_JSON_MANDATORY },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {},
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &context);
        if (r != 0)
                return r;

        r = verify_polkit(&context, link, "org.freedesktop.sysupdate1.check",
                        (const char**) STRV_MAKE(
                                        "class", target_class_to_string(context.target_identifier.class),
                                        "offline", "0",
                                        context.target_identifier.name ? "name" : NULL, context.target_identifier.name));
        if (r <= 0)
                return r;

        if (getenv_bool("SYSTEMD_SYSUPDATE_NO_VERIFY") > 0)
                context.verify = 0;

        /* CheckNew is always online */
        context.offline = false;

        r = context_load_online_from_target(
                        &context,
                        PROCESS_IMAGE_READ_ONLY,
                        READ_DEFINITIONS_REQUIRES_ENABLED_TRANSFERS|
                        READ_DEFINITIONS_REQUIRES_ANY_TRANSFERS);
        if (r == -ENOENT)
                return sd_varlink_error(link, "io.systemd.SysUpdate.NoSuchTarget", NULL);
        if (r < 0)
                return r;

        if (context.candidate)
                r = sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_STRING("available", context.candidate->version));
        else
                r = sd_varlink_error(link, "io.systemd.SysUpdate.NoUpdateNeeded", NULL);
        if (r < 0)
                return r;

        return 0;
}

typedef enum {
        UPDATE_ACTION_ACQUIRE = 1 << 0,
        UPDATE_ACTION_INSTALL = 1 << 1,
} UpdateActionFlags;

static int verb_update_impl(int argc, char **argv, UpdateActionFlags action_flags) {
        _cleanup_free_ char *booted_version = NULL;
        UpdateSet *applied = NULL;
        const char *version;
        int r;

        assert(argc <= 2);
        version = argc >= 2 ? argv[1] : NULL;

        _cleanup_(context_done) Context context = CONTEXT_NULL;
        r = context_from_cmdline(&context);
        if (r < 0)
                return r;

        if (context.feature_select != SELECT_EXPLICIT)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--feature-all/--feature-suggested is not supported for '%s'.", argv[0]);
        if (context.component_select != SELECT_EXPLICIT)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "--component-all/--component-suggested currently not supported for '%s'.", argv[0]);

        if (context.instances_max < 2)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                      "The --instances-max= argument must be >= 2 while updating");

        if (context.reboot) {
                /* If automatic reboot on completion is requested, let's first determine the currently booted image */

                r = parse_os_release(context.root, "IMAGE_VERSION", &booted_version);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse /etc/os-release: %m");
                if (!booted_version)
                        return log_error_errno(SYNTHETIC_ERRNO(ENODATA), "/etc/os-release lacks IMAGE_VERSION field.");
        }

        bool installed = false;
        int ret = 0;

        r = context_load_online(
                        &context,
                        /* process_image_flags= */ 0,
                        READ_DEFINITIONS_REQUIRES_ENABLED_TRANSFERS|
                        READ_DEFINITIONS_REQUIRES_ANY_TRANSFERS|
                        READ_DEFINITIONS_REQUIRES_ENABLED_COMPONENT);
        if (r < 0) {
                if (r != -ENOENT)
                        return r;

                /* No transfer files found. In that case, still do the installdb cleanup below */
                RET_GATHER(ret, r);
        } else {
                if (action_flags & UPDATE_ACTION_ACQUIRE)
                        r = context_acquire(&context, version);
                else
                        r = context_process_partial_and_pending(&context, version);
                if (r < 0)
                        return r;

                if (FLAGS_SET(action_flags, UPDATE_ACTION_INSTALL) && r > 0) { /* installation of update indicated */
                        r = context_install(&context, version, &applied);
                        if (r < 0)
                                return r;

                        installed = r > 0;
                }

                /* context_install() returns > 0 (and emits a notification) only if it actually applied an update. If
                 * nothing was applied but SYSTEMD_SYSUPDATE_FORCE_NOTIFY=1 is set, still notify subscribers (without a
                 * resource list), so e.g. a kernel/policy refresh can be triggered unconditionally. */
                if ((action_flags & UPDATE_ACTION_INSTALL) && !installed) {
                        int f = secure_getenv_bool("SYSTEMD_SYSUPDATE_FORCE_NOTIFY");
                        if (f < 0 && f != -ENXIO)
                                log_debug_errno(f, "Failed to parse $SYSTEMD_SYSUPDATE_FORCE_NOTIFY, ignoring: %m");
                        if (f > 0)
                                (void) context_notify_subscribers(&context, /* us= */ NULL);
                }
        }

        if (context.cleanup > 0)
                RET_GATHER(ret, installdb_cleanup_component(&context));

        if (installed) {
                /* We installed something, yay */

                if (context.reboot) {
                        assert(applied);
                        assert(booted_version);

                        if (strverscmp_improved(applied->version, booted_version) > 0) {
                                log_notice("Newly installed version is newer than booted version, rebooting.");
                                RET_GATHER(ret, reboot_now());
                        } else if (strverscmp_improved(applied->version, booted_version) == 0 &&
                                   FLAGS_SET(applied->flags, UPDATE_INCOMPLETE)) {
                                log_notice("Currently booted version was incomplete and has been repaired, rebooting.");
                                RET_GATHER(ret, reboot_now());
                        } else
                                log_info("Booted version is newer or identical to newly installed version, not rebooting.");
                }
        }

        return ret;
}

VERB(verb_update, "update", "[VERSION]", VERB_ANY, 2, 0,
     "Install new version now");
static int verb_update(int argc, char *argv[], uintptr_t _data, void *userdata) {
        UpdateActionFlags flags = UPDATE_ACTION_INSTALL;

        if (!arg_offline)
                flags |= UPDATE_ACTION_ACQUIRE;

        return verb_update_impl(argc, argv, flags);
}

VERB(verb_acquire, "acquire", "[VERSION]", VERB_ANY, 2, 0,
     "Acquire (download) new version now");
static int verb_acquire(int argc, char *argv[], uintptr_t _data, void *userdata) {
        return verb_update_impl(argc, argv, UPDATE_ACTION_ACQUIRE);
}

VERB_NOARG(verb_vacuum, "vacuum",
           "Make room, by deleting old versions");
static int verb_vacuum(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(context_done) Context context = CONTEXT_NULL;
        int r;

        assert(argc <= 1);

        r = context_from_cmdline(&context);
        if (r < 0)
                return r;

        if (context.feature_select != SELECT_EXPLICIT)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--feature-all/--feature-suggested is not supported for '%s'.", argv[0]);
        if (context.component_select != SELECT_EXPLICIT)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "--component-all/--component-suggested currently not supported for '%s'.", argv[0]);

        if (context.instances_max < 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                      "The --instances-max= argument must be >= 1 while vacuuming");

        r = context_load_offline(
                        &context,
                        /* process_image_flags= */ 0,
                        READ_DEFINITIONS_REQUIRES_ANY_TRANSFERS);
        if (r < 0)
                return r;

        return context_vacuum(&context, 0, NULL);
}

VERB_NOARG(verb_cleanup, "cleanup", "Clean up orphaned files");
static int verb_cleanup(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(context_done) Context context = CONTEXT_NULL;
        int r;

        assert(argc <= 1);

        r = context_from_cmdline(&context);
        if (r < 0)
                return r;

        if (context.cleanup == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invocation of 'cleanup' with --cleanup=no is contradictory, refusing.");

        if (context.feature_select != SELECT_EXPLICIT)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--feature-all/--feature-suggested is not supported for '%s'.", argv[0]);
        if (!IN_SET(context.component_select, SELECT_EXPLICIT, SELECT_ALL))
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "--component-suggested currently not supported for '%s'.", argv[0]);

        r = context_load_offline(
                        &context,
                        /* process_image_flags= */ 0,
                        /* read_definitions_flags= */ 0);
        if (r < 0)
                return r;

        int ret = 0;
        RET_GATHER(ret, installdb_cleanup_component(&context));

        if (context.component_select == SELECT_ALL) {
                _cleanup_strv_free_ char **z = NULL;
                r = installdb_list_components(&context, &z);
                if (r < 0)
                        return log_error_errno(r, "Failed to enumerate components: %m");

                STRV_FOREACH(i, z) {
                        _cleanup_(context_done) Context component_context = CONTEXT_NULL;

                        r = context_from_cmdline(&component_context);
                        if (r < 0)
                                return r;

                        /* Override the component with our iter. This needs to be done in a fresh Context
                         * as the installdb_fd and other state are specific to the component. */
                        r = free_and_strdup_warn(&component_context.component, *i);
                        if (r < 0)
                                return r;

                        r = context_load_offline(
                                        &component_context,
                                        /* process_image_flags= */ 0,
                                        /* read_definitions_flags= */ 0);
                        if (r < 0)
                                return r;

                        RET_GATHER(ret, installdb_cleanup_component(&component_context));
                }
        }

        return ret;
}

VERB(verb_pending_or_reboot, "pending", NULL, 1, 1, 0,
     "Report whether a newer version is installed than currently booted");
VERB(verb_pending_or_reboot, "reboot", NULL, 1, 1, 0,
     "Reboot if a newer version is installed than booted");
static int verb_pending_or_reboot(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(context_done) Context context = CONTEXT_NULL;
        _cleanup_free_ char *booted_version = NULL;
        int r;

        assert(argc == 1);

        r = context_from_cmdline(&context);
        if (r < 0)
                return r;

        if (context.image || context.root)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "The --root=/--image= switches may not be combined with the '%s' operation.", argv[0]);

        if (context.feature_select != SELECT_EXPLICIT)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--feature-all/--feature-suggested is not supported for '%s'.", argv[0]);
        if (context.component || context.component_select != SELECT_EXPLICIT)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "The --component=, --component-all and --component-suggested switches may not be combined with the '%s' operation, which only applies to the booted OS version.", argv[0]);

        r = context_load_offline(
                        &context,
                        /* process_image_flags= */ 0,
                        READ_DEFINITIONS_REQUIRES_ENABLED_TRANSFERS|
                        READ_DEFINITIONS_REQUIRES_ANY_TRANSFERS|
                        READ_DEFINITIONS_REQUIRES_ENABLED_COMPONENT);
        if (r < 0)
                return r;

        log_info("Determining installed update sets%s", glyph(GLYPH_ELLIPSIS));

        r = context_discover_update_sets_by_flag(&context, UPDATE_INSTALLED);
        if (r < 0)
                return r;
        if (!context.newest_installed)
                return log_error_errno(SYNTHETIC_ERRNO(ENODATA), "Couldn't find any suitable installed versions.");

        r = parse_os_release(context.root, "IMAGE_VERSION", &booted_version);
        if (r < 0) /* yes, context.root is NULL here, but we have to pass something, and it's a lot more readable
                    * if we see what the first argument is about */
                return log_error_errno(r, "Failed to parse /etc/os-release: %m");
        if (!booted_version)
                return log_error_errno(SYNTHETIC_ERRNO(ENODATA), "/etc/os-release lacks IMAGE_VERSION= field.");

        r = strverscmp_improved(context.newest_installed->version, booted_version);
        if (r > 0) {
                log_notice("Newest installed version '%s' is newer than booted version '%s'.%s",
                           context.newest_installed->version, booted_version,
                           streq(argv[0], "pending") ? " Reboot recommended." : "");

                if (streq(argv[0], "reboot"))
                        return reboot_now();

                return EXIT_SUCCESS;
        } else if (r == 0)
                log_info("Newest installed version '%s' matches booted version '%s'.",
                         context.newest_installed->version, booted_version);
        else
                log_warning("Newest installed version '%s' is older than booted version '%s'.",
                            context.newest_installed->version, booted_version);

        if (streq(argv[0], "pending")) /* When called as 'pending' tell the caller via failure exit code that there's nothing newer installed */
                return EXIT_FAILURE;

        return EXIT_SUCCESS;
}

static int context_list_components(Context *context, char ***ret_component_names, bool *ret_has_default_component) {
        int r;

        assert(context);

        _cleanup_strv_free_ char **z = NULL;
        r = get_component_list(context->root, &z);
        if (r < 0)
                return r;

        if (ret_component_names)
                *ret_component_names = TAKE_PTR(z);

        /* Does the system have at least one transfer file in /etc/sysupdate.d, which can be considered a
         * TARGET_HOST? See target_get_argument() in sysupdated.c */
        if (ret_has_default_component)
                *ret_has_default_component =
                        !context->definitions &&
                        !context->component &&
                        !context->root &&
                        !context->image &&
                        context->n_transfers > 0;

        return 0;
}

static int context_component_is_suggested(Context *c) {
        assert(c);

        /* Only applies to components, not to the main system */
        if (!c->component)
                return -ENOTTY;

        if (c->component_suggest >= 0)
                return c->component_suggest;

        if (!c->component_suggest_on) /* no condition → false */
                return false;

        return condition_test_list(c->component_suggest_on, environ, suggest_on_type_to_string, /* logger= */ NULL, /* userdata= */ NULL);
}

VERB_NOARG(verb_components, "components",
           "Show list of components");
static int verb_components(int argc, char *argv[], uintptr_t _data, void *userdata) {
        int r;

        assert(argc <= 1);

        _cleanup_(context_done) Context context = CONTEXT_NULL;
        r = context_from_cmdline(&context);
        if (r < 0)
                return r;

        if (context.feature_select != SELECT_EXPLICIT)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--feature-all/--feature-suggested is not supported for '%s'.", argv[0]);
        if (context.component_select != SELECT_EXPLICIT)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "--component-all/--component-suggested currently not supported for '%s'.", argv[0]);
        if (context.definitions)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "The --definitions= switch may not be combined with '%s'.", argv[0]);

        r = context_load_offline(
                        &context,
                        /* process_image_flags= */ 0,
                        /* read_definitions_flags= */ 0);
        if (r < 0)
                return r;

        _cleanup_strv_free_ char **component_names = NULL;
        bool has_default_component = false;
        r = context_list_components(&context, &component_names, &has_default_component);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate components: %m");

        if (!sd_json_format_enabled(arg_json_format_flags)) {
                if (!has_default_component && strv_isempty(component_names)) {
                        log_info("No components defined.");
                        return 0;
                }

                _cleanup_(table_unrefp) Table *t = table_new("enabled", "suggested", "component", "description", "documentation");
                if (!t)
                        return log_oom();

                table_set_ersatz_string(t, TABLE_ERSATZ_DASH);

                if (has_default_component) {
                        r = table_add_many(
                                        t,
                                        TABLE_EMPTY,
                                        TABLE_EMPTY,
                                        TABLE_STRING, "<default>",
                                        TABLE_SET_COLOR, ansi_highlight(),
                                        TABLE_STRING, "Default Component",
                                        TABLE_EMPTY);
                        if (r < 0)
                                return table_log_add_error(r);
                }

                STRV_FOREACH(i, component_names) {
                        _cleanup_(context_done) Context cc = CONTEXT_NULL;

                        r = context_from_base_with_component(
                                        &context,
                                        *i,
                                        &cc);
                        if (r < 0)
                                return r;

                        r = context_load_offline(
                                        &cc,
                                        /* process_image_flags= */ 0,
                                        /* read_definitions_flags= */ 0);
                        if (r == -ENOMEM)
                                return r;
                        if (r < 0)
                                continue;

                        r = table_add_many(
                                        t,
                                        TABLE_BOOLEAN_CHECKMARK, cc.component_enabled,
                                        TABLE_SET_COLOR, ansi_highlight_green_red(cc.component_enabled));
                        if (r < 0)
                                return table_log_add_error(r);

                        r = context_component_is_suggested(&cc);
                        if (r < 0)
                                r = table_add_many(t, TABLE_EMPTY);
                        else
                                r = table_add_many(t, TABLE_BOOLEAN_CHECKMARK, r);
                        if (r < 0)
                                return table_log_add_error(r);

                        const char *doc = cc.component_documentation ? cc.component_documentation[0] : NULL;

                        r = table_add_many(
                                        t,
                                        TABLE_STRING, *i,
                                        TABLE_STRING, cc.component_description,
                                        TABLE_STRING, doc,
                                        TABLE_SET_URL, doc);
                        if (r < 0)
                                return table_log_add_error(r);
                }

                return table_print_with_pager(t, arg_json_format_flags, arg_pager_flags, arg_legend);
        } else {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *json = NULL;

                r = sd_json_buildo(&json, SD_JSON_BUILD_PAIR_BOOLEAN("default", has_default_component),
                                          SD_JSON_BUILD_PAIR_STRV("components", component_names));
                if (r < 0)
                        return log_error_errno(r, "Failed to create JSON: %m");

                r = sd_json_variant_dump(json, arg_json_format_flags, stdout, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to print JSON: %m");
        }

        return 0;
}

static int vl_method_list_targets(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        _cleanup_(context_done) Context context = CONTEXT_NULL;
        _cleanup_set_free_ Set *targets = NULL;
        int r;

        assert(link);

        r = sd_varlink_dispatch(link, parameters, NULL, NULL);
        if (r != 0)
                return r;

        /* Listing targets doesn’t require a polkit check */

        if (getenv_bool("SYSTEMD_SYSUPDATE_NO_VERIFY") > 0)
                context.verify = 0;

        /* ListTargets is always offline */
        context.offline = true;

        r = context_load_offline(
                        &context,
                        PROCESS_IMAGE_READ_ONLY,
                        /* read_definitions_flags= */ 0);
        if (r < 0)
                return r;

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *l = NULL;

        r = context_enumerate_targets(&context, &targets);
        if (r < 0)
                return r;

        /* Sort to ensure consistent ordering */
        size_t n;
        _cleanup_free_ TargetIdentifier **sorted = NULL;
        r = set_dump_sorted(targets, (void***) &sorted, &n);
        if (r < 0)
                return log_oom();

        FOREACH_ARRAY(p, sorted, n) {
                TargetIdentifier *target_identifier = *p;
                const char *name = (target_identifier->class != TARGET_HOST) ? target_identifier->name : NULL;

                r = sd_json_variant_append_arraybo(&l,
                                SD_JSON_BUILD_PAIR_OBJECT("id",
                                                JSON_BUILD_PAIR_ENUM("class", target_class_to_string(target_identifier->class)),
                                                SD_JSON_BUILD_PAIR_STRING("name", name)));
                if (r < 0)
                        return r;
        }

        if (!l) {
                r = sd_json_variant_new_array(&l, NULL, 0);
                if (r < 0)
                        return r;
        }

        return sd_varlink_replybo(link,
                        SD_JSON_BUILD_PAIR_VARIANT("targets", l));
}

VERB(verb_enable_component, "enable-component", "COMPONENT…", 1, VERB_ANY, 0,
     "Enable component");
VERB(verb_enable_component, "disable-component", "COMPONENT…", 1, VERB_ANY, 0,
     "Disable component");
static int verb_enable_component(int argc, char *argv[], uintptr_t _data, void *userdata) {
        bool enable = streq(argv[0], "enable-component");
        int r;

        _cleanup_(context_done) Context context = CONTEXT_NULL;
        r = context_from_cmdline(&context);
        if (r < 0)
                return r;

        if (context.feature_select != SELECT_EXPLICIT)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--feature-all/--feature-suggested is not supported for '%s'.", argv[0]);
        if (context.definitions)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "The --definitions= switch may not be combined with '%s'.", argv[0]);

        char **arguments, *array[2];
        if (argc > 1) {
                if (context.component || context.component_select != SELECT_EXPLICIT)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Either specify component names as positional parameter or via --component=/--component-all/--component-suggested, not both.");

                arguments = strv_skip(argv, 1);

        } else if (context.component_select == SELECT_EXPLICIT) {
                if (!context.component)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "No component specified.");

                array[0] = context.component;
                array[1] = NULL;
                arguments = array;
        } else {
                assert(!context.component);
                arguments = NULL;
        }

        STRV_FOREACH(name, arguments)
                if (!component_name_valid(*name))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Component name invalid: %s", *name);

        r = context_load_offline(
                        &context,
                        /* process_image_flags= */ 0,
                        /* read_definitions_flags= */ 0);
        if (r < 0)
                return r;

        _cleanup_strv_free_ char **component_names = NULL;
        r = context_list_components(&context, &component_names, /* ret_has_default_component= */ NULL);
        if (r < 0)
                return r;

        _cleanup_strv_free_ char **suggested = NULL;

        switch (context.component_select) {

        case SELECT_EXPLICIT:
                STRV_FOREACH(name, arguments)
                        if (!strv_contains(component_names, *name))
                                return log_error_errno(SYNTHETIC_ERRNO(ENOENT), "Component not found: %s", *name);
                break;

        case SELECT_ALL:
                assert(!arguments);
                arguments = component_names;
                break;

        case SELECT_SUGGESTED:
                assert(!arguments);
                STRV_FOREACH(name, component_names) {
                        _cleanup_(context_done) Context cc = CONTEXT_NULL;

                        r = context_from_base_with_component(&context, *name, &cc);
                        if (r < 0)
                                return r;

                        r = context_load_offline(
                                        &cc,
                                        /* process_image_flags= */ 0,
                                        /* read_definitions_flags= */ 0);
                        if (r < 0)
                                continue;

                        r = context_component_is_suggested(&cc);
                        if (r < 0) {
                                log_warning_errno(r, "Failed to determine whether '%s' shall be enabled, skipping: %m", *name);
                                continue;
                        }

                        /* This reconciles the system with the suggestions: on 'enable-component' we act on
                         * the components that are suggested, on 'disable-component' we act on the ones that
                         * are not. Hence pick the components whose suggestion state matches the operation. */
                        if (!!r != !!enable) {
                                log_debug("Skipping '%s'.", *name);
                                continue;
                        }

                        log_info("%s '%s'.", enable ? "Enabling" : "Disabling", *name);

                        if (strv_extend(&suggested, *name) < 0)
                                return log_oom();
                }

                arguments = suggested;
                break;

        default:
                assert_not_reached();
        }

        if (strv_isempty(arguments)) {
                log_info("No components selected.");
                return 0;
        }

        /* Component definition files live directly below the configuration directories, hence the drop-in
         * goes right next to them below /etc. */
        _cleanup_free_ char *dropin_dir = path_join(context.root, SYSCONF_DIR);
        if (!dropin_dir)
                return log_oom();

        STRV_FOREACH(name, arguments) {
                _cleanup_free_ char *fname = strjoin("sysupdate.", *name, ".component");
                if (!fname)
                        return log_oom();

                /* We assume that no sysadmin will name their config 50-systemd-sysupdate-enabled.conf */
                r = write_drop_in_format(
                                dropin_dir,
                                fname,
                                50, "systemd-sysupdate-enabled",
                                "# Generated via 'systemd-sysupdate %s'\n\n"
                                "[Component]\n"
                                "Enabled=%s\n",
                                argv[0],
                                yes_no(enable));
                if (r < 0)
                        return log_error_errno(r, "Failed to write drop-in for component '%s': %m", *name);

                log_info("Component '%s' %s.", *name, enable ? "enabled" : "disabled");
        }

        return 0;
}

static int help(void) {
        _cleanup_(table_unrefp) Table *common_options = NULL, *options = NULL, *verbs = NULL;
        int r;

        r = verbs_get_help_table(&verbs);
        if (r < 0)
                return r;

        r = option_parser_get_help_table(&common_options);
        if (r < 0)
                return r;

        r = option_parser_get_help_table_group("Options", &options);
        if (r < 0)
                return r;

        (void) table_sync_column_widths(0, verbs, common_options, options);

        help_cmdline("[OPTIONS…] [VERSION]");
        help_abstract("Update OS images.");

        help_section("Commands");
        r = table_print_or_warn(verbs);
        if (r < 0)
                return r;

        r = table_print_or_warn(common_options);
        if (r < 0)
                return r;

        help_section("Options");
        r = table_print_or_warn(options);
        if (r < 0)
                return r;

        help_man_page_reference("systemd-sysupdate", "8");
        return 0;
}

VERB_COMMON_HELP_HIDDEN(help);

static int parse_argv(int argc, char *argv[], char ***remaining_args) {
        assert(argc >= 0);
        assert(argv);
        assert(remaining_args);

        OptionParser opts = { argc, argv };
        int r;

        FOREACH_OPTION_OR_RETURN(c, &opts)
                switch (c) {

                OPTION_COMMON_HELP:
                        return help();

                OPTION_COMMON_VERSION:
                        return version();

                OPTION_GROUP("Options"):
                        break;

                OPTION('C', "component", "NAME",
                       "Select component to update"):
                        if (isempty(opts.arg)) {
                                arg_component = mfree(arg_component);
                                arg_component_select = SELECT_EXPLICIT;
                                break;
                        }

                        if (!component_name_valid(opts.arg))
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Component name invalid: %s", opts.arg);

                        r = free_and_strdup_warn(&arg_component, opts.arg);
                        if (r < 0)
                                return r;

                        arg_component_select = SELECT_EXPLICIT;
                        break;

                OPTION('A', "component-all", NULL, "Select all components"):
                        arg_component = mfree(arg_component);
                        arg_component_select = SELECT_ALL;
                        break;

                OPTION('S', "component-suggested", NULL, "Select all suggested components"):
                        arg_component = mfree(arg_component);
                        arg_component_select = SELECT_SUGGESTED;
                        break;

                OPTION('a', "feature-all", NULL, "Select all features"):
                        arg_feature_select = SELECT_ALL;
                        break;

                OPTION('s', "feature-suggested", NULL, "Select all suggested features"):
                        arg_feature_select = SELECT_SUGGESTED;
                        break;

                OPTION_LONG("definitions", "DIR",
                            "Find transfer definitions in specified directory"):
                        r = parse_path_argument(opts.arg, /* suppress_root= */ false, &arg_definitions);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("root", "PATH",
                            "Operate on an alternate filesystem root"):
                        r = parse_path_argument(opts.arg, /* suppress_root= */ false, &arg_root);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("image", "PATH",
                            "Operate on disk image as filesystem root"):
                        r = parse_path_argument(opts.arg, /* suppress_root= */ false, &arg_image);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("image-policy", "POLICY",
                            "Specify disk image dissection policy"):
                        r = parse_image_policy_argument(opts.arg, &arg_image_policy);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("transfer-source", "PATH",
                            "Specify the directory to transfer sources from"):
                        r = parse_path_argument(opts.arg, /* suppress_root= */ false, &arg_transfer_source);
                        if (r < 0)
                                return r;

                        break;

                OPTION('m', "instances-max", "INT",
                       "How many instances to maintain"):
                        r = safe_atou64(opts.arg, &arg_instances_max);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --instances-max= parameter: %s", opts.arg);

                        break;

                OPTION_LONG("sync", "BOOL",
                            "Controls whether to sync data to disk"):
                        r = parse_boolean_argument("--sync=", opts.arg, &arg_sync);
                        if (r < 0)
                                return r;
                        break;

                OPTION_LONG("verify", "BOOL",
                            "Force signature verification on or off"): {
                        bool b;

                        r = parse_boolean_argument("--verify=", opts.arg, &b);
                        if (r < 0)
                                return r;

                        arg_verify = b;
                        break;
                }

                OPTION_LONG("reboot", NULL,
                            "Reboot after updating to newer version"):
                        arg_reboot = true;
                        break;

                OPTION_LONG("offline", NULL,
                            "Do not fetch metadata from the network"):
                        arg_offline = true;
                        break;

                OPTION_LONG("cleanup", "BOOL", "Clean up orphaned files after completing update"): {
                        bool b;

                        r = parse_boolean_argument("--cleanup=", opts.arg, &b);
                        if (r < 0)
                                return r;

                        arg_cleanup = b;
                        break;
                }

                OPTION_COMMON_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                OPTION_COMMON_NO_LEGEND:
                        arg_legend = false;
                        break;

                OPTION_COMMON_JSON:
                        r = parse_json_argument(opts.arg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;

                        break;
                }

        if (arg_image && arg_root)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Please specify either --root= or --image=, the combination of both is not supported.");

        if (arg_image || arg_root) {
                if (arg_reboot)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "The --reboot switch may not be combined with --root= or --image=.");

                if (arg_definitions)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "The --definitions= switch may not be combined with --root= or --image=.");
        }

        if ((arg_component || arg_component_select != SELECT_EXPLICIT)) {
                if (arg_reboot)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "The --reboot switch may not be combined with --component=/--component-all/--component-suggested, as automatic reboots only apply to the booted OS version.");

                if (arg_definitions)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "The --definitions= and --component=/--component-all/--component-suggested switches may not be combined.");
        }

        r = sd_varlink_invocation(SD_VARLINK_ALLOW_ACCEPT);
        if (r < 0)
                return log_error_errno(r, "Failed to check if invoked in Varlink mode: %m");
        if (r > 0)
                arg_varlink = true;

        *remaining_args = option_parser_get_args(&opts);
        return 1;
}

static int vl_server(void) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *varlink_server = NULL;
        _cleanup_(server_done) Server server = SERVER_NULL;
        int r;

        r = varlink_server_new(&varlink_server,
                               SD_VARLINK_SERVER_ACCOUNT_UID|SD_VARLINK_SERVER_INHERIT_USERDATA,
                               &server);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate Varlink server: %m");

        r = sd_varlink_server_add_interface(varlink_server, &vl_interface_io_systemd_SysUpdate);
        if (r < 0)
                return log_error_errno(r, "Failed to add Varlink interface: %m");

        r = sd_varlink_server_bind_method_many(
                        varlink_server,
                        "io.systemd.SysUpdate.CheckNew",     vl_method_check_new,
                        "io.systemd.SysUpdate.ListFeatures", vl_method_list_features,
                        "io.systemd.SysUpdate.ListTargets",  vl_method_list_targets);
        if (r < 0)
                return log_error_errno(r, "Failed to bind Varlink method: %m");

        r = sd_varlink_server_loop_auto(varlink_server);
        if (r < 0)
                return log_error_errno(r, "Failed to run Varlink event loop: %m");

        return 0;
}

static int run(int argc, char *argv[]) {
        int r;

        LIBAPPARMOR_NOTE(recommended);
        LIBAUDIT_NOTE(recommended);
        LIBBLKID_NOTE(recommended);
        LIBCRYPTO_NOTE(suggested);
        LIBCRYPTSETUP_NOTE(suggested);
        LIBMOUNT_NOTE(recommended);
        LIBSELINUX_NOTE(recommended);
        LIBTSS2_ESYS_NOTE(suggested);
        LIBTSS2_MU_NOTE(suggested);
        LIBTSS2_RC_NOTE(suggested);

        log_setup();

        char **args = NULL;
        r = parse_argv(argc, argv, &args);
        if (r <= 0)
                return r;

        if (arg_varlink)
                return vl_server(); /* Invocation as Varlink service */

        return dispatch_verb(args, NULL);
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
