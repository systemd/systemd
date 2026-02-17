/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sd-id128.h"

#include "alloc-util.h"
#include "build-path.h"
#include "chase.h"
#include "conf-parser.h"
#include "dirent-util.h"
#include "errno-util.h"
#include "event-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fs-util.h"
#include "glyph-util.h"
#include "gpt.h"
#include "hashmap.h"
#include "hexdecoct.h"
#include "install-file.h"
#include "mkdir.h"
#include "notify-recv.h"
#include "parse-helpers.h"
#include "parse-util.h"
#include "percent-util.h"
#include "pidref.h"
#include "process-util.h"
#include "rm-rf.h"
#include "signal-util.h"
#include "specifier.h"
#include "stdio-util.h"
#include "strv.h"
#include "sync-util.h"
#include "sysupdate.h"
#include "sysupdate-feature.h"
#include "sysupdate-instance.h"
#include "sysupdate-pattern.h"
#include "sysupdate-resource.h"
#include "sysupdate-transfer.h"
#include "time-util.h"
#include "web-util.h"

/* Default value for InstancesMax= for fs object targets */
#define DEFAULT_FILE_INSTANCES_MAX 3

Transfer* transfer_free(Transfer *t) {
        if (!t)
                return NULL;

        free(t->temporary_partial_path);
        free(t->temporary_pending_path);

        free(t->id);

        free(t->min_version);
        strv_free(t->protected_versions);
        free(t->current_symlink);
        free(t->final_path);

        strv_free(t->features);
        strv_free(t->requisite_features);

        strv_free(t->changelog);
        strv_free(t->appstream);

        partition_info_destroy(&t->partition_info);
        free(t->final_partition_label);

        resource_destroy(&t->source);
        resource_destroy(&t->target);

        return mfree(t);
}

Transfer* transfer_new(Context *ctx) {
        Transfer *t;

        t = new(Transfer, 1);
        if (!t)
                return NULL;

        *t = (Transfer) {
                .source.type = _RESOURCE_TYPE_INVALID,
                .target.type = _RESOURCE_TYPE_INVALID,
                .remove_temporary = true,
                .mode = MODE_INVALID,
                .tries_left = UINT64_MAX,
                .tries_done = UINT64_MAX,
                .verify = true,

                /* the three flags, as configured by the user */
                .no_auto = -1,
                .read_only = -1,
                .growfs = -1,

                /* the read only flag, as ultimately determined */
                .install_read_only = -1,

                .partition_info = PARTITION_INFO_NULL,

                .context = ctx,
        };

        return t;
}

static int config_parse_protect_version(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_free_ char *resolved = NULL;
        char ***protected_versions = ASSERT_PTR(data);
        int r;

        assert(rvalue);

        r = specifier_printf(rvalue, NAME_MAX, specifier_table, arg_root, NULL, &resolved);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to expand specifiers in ProtectVersion=, ignoring: %s", rvalue);
                return 0;
        }

        if (!version_is_valid(resolved))  {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "ProtectVersion= string is not valid, ignoring: %s", resolved);
                return 0;
        }

        r = strv_extend(protected_versions, resolved);
        if (r < 0)
                return log_oom();

        return 0;
}

static int config_parse_min_version(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_free_ char *resolved = NULL;
        char **version = ASSERT_PTR(data);
        int r;

        assert(rvalue);

        r = specifier_printf(rvalue, NAME_MAX, specifier_table, arg_root, NULL, &resolved);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to expand specifiers in MinVersion=, ignoring: %s", rvalue);
                return 0;
        }

        if (!version_is_valid(rvalue)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "MinVersion= string is not valid, ignoring: %s", resolved);
                return 0;
        }

        return free_and_replace(*version, resolved);
}

static int config_parse_url_specifiers(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {
        char ***s = ASSERT_PTR(data);
        _cleanup_free_ char *resolved = NULL;
        int r;

        assert(rvalue);

        if (isempty(rvalue)) {
                *s = strv_free(*s);
                return 0;
        }

        r = specifier_printf(rvalue, NAME_MAX, specifier_table, arg_root, NULL, &resolved);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to expand specifiers in %s=, ignoring: %s", lvalue, rvalue);
                return 0;
        }

        if (!http_url_is_valid(resolved)) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "%s= URL is not valid, ignoring: %s", lvalue, rvalue);
                return 0;
        }

        r = strv_push(s, TAKE_PTR(resolved));
        if (r < 0)
                return log_oom();

        return 0;
}

static int config_parse_current_symlink(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_free_ char *resolved = NULL;
        char **current_symlink = ASSERT_PTR(data);
        int r;

        assert(rvalue);

        r = specifier_printf(rvalue, NAME_MAX, specifier_table, arg_root, NULL, &resolved);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to expand specifiers in CurrentSymlink=, ignoring: %s", rvalue);
                return 0;
        }

        r = path_simplify_and_warn(resolved, 0, unit, filename, line, lvalue);
        if (r < 0)
                return 0;

        return free_and_replace(*current_symlink, resolved);
}

static int config_parse_instances_max(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        uint64_t *instances_max = data, i;
        int r;

        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                *instances_max = 0; /* Revert to default logic, see transfer_read_definition() */
                return 0;
        }

        r = safe_atou64(rvalue, &i);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse InstancesMax= value, ignoring: %s", rvalue);
                return 0;
        }

        if (i < 2) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "InstancesMax= value must be at least 2, bumping: %s", rvalue);
                *instances_max = 2;
        } else
                *instances_max = i;

        return 0;
}

static int config_parse_resource_pattern(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        char ***patterns = ASSERT_PTR(data);
        int r;

        assert(rvalue);

        if (isempty(rvalue)) {
                *patterns = strv_free(*patterns);
                return 0;
        }

        for (;;) {
                _cleanup_free_ char *word = NULL, *resolved = NULL;

                r = extract_first_word(&rvalue, &word, NULL, EXTRACT_CUNESCAPE|EXTRACT_UNESCAPE_RELAX);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to extract first pattern from MatchPattern=, ignoring: %s", rvalue);
                        return 0;
                }
                if (r == 0)
                        break;

                r = specifier_printf(word, NAME_MAX, specifier_table, arg_root, NULL, &resolved);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to expand specifiers in MatchPattern=, ignoring: %s", rvalue);
                        return 0;
                }

                if (!pattern_valid(resolved))
                        return log_syntax(unit, LOG_ERR, filename, line, SYNTHETIC_ERRNO(EINVAL),
                                          "MatchPattern= string is not valid, refusing: %s", resolved);

                r = strv_consume(patterns, TAKE_PTR(resolved));
                if (r < 0)
                        return log_oom();
        }

        strv_uniq(*patterns);
        return 0;
}

static int config_parse_resource_path(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {
        _cleanup_free_ char *resolved = NULL;
        Resource *rr = ASSERT_PTR(data);
        int r;

        assert(rvalue);

        if (streq(rvalue, "auto")) {
                rr->path_auto = true;
                rr->path = mfree(rr->path);
                return 0;
        }

        r = specifier_printf(rvalue, PATH_MAX-1, specifier_table, arg_root, NULL, &resolved);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to expand specifiers in Path=, ignoring: %s", rvalue);
                return 0;
        }

        /* Note that we don't validate the path as being absolute or normalized. We'll do that in
         * transfer_read_definition() as we might not know yet whether Path refers to a URL or a file system
         * path. */

        rr->path_auto = false;
        return free_and_replace(rr->path, resolved);
}

static DEFINE_CONFIG_PARSE_ENUM(config_parse_resource_type, resource_type, ResourceType);

static DEFINE_CONFIG_PARSE_ENUM_WITH_DEFAULT(config_parse_resource_path_relto, path_relative_to, PathRelativeTo,
                                             PATH_RELATIVE_TO_ROOT);

static int config_parse_resource_ptype(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Resource *rr = ASSERT_PTR(data);
        int r;

        assert(rvalue);

        r = gpt_partition_type_from_string(rvalue, &rr->partition_type);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse partition type, ignoring: %s", rvalue);
                return 0;
        }

        rr->partition_type_set = true;
        return 0;
}

static int config_parse_partition_uuid(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Transfer *t = ASSERT_PTR(data);
        int r;

        assert(rvalue);

        r = sd_id128_from_string(rvalue, &t->partition_uuid);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse partition UUID, ignoring: %s", rvalue);
                return 0;
        }

        t->partition_uuid_set = true;
        return 0;
}

static int config_parse_partition_flags(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Transfer *t = ASSERT_PTR(data);
        int r;

        assert(rvalue);

        r = safe_atou64(rvalue, &t->partition_flags);
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse partition flags, ignoring: %s", rvalue);
                return 0;
        }

        t->partition_flags_set = true;
        return 0;
}

static bool transfer_decide_if_enabled(Transfer *t, Hashmap *known_features) {
        assert(t);

        /* Requisite feature disabled -> transfer disabled */
        STRV_FOREACH(id, t->requisite_features) {
                Feature *f = hashmap_get(known_features, *id);
                if (!f || !f->enabled) /* missing features are implicitly disabled */
                        return false;
        }

        /* No features defined -> transfer implicitly enabled */
        if (strv_isempty(t->features))
                return true;

        /* At least one feature enabled -> transfer enabled */
        STRV_FOREACH(id, t->features) {
                Feature *f = hashmap_get(known_features, *id);
                if (f && f->enabled)
                        return true;
        }

        /* All listed features disabled -> transfer disabled */
        return false;
}

int transfer_read_definition(Transfer *t, const char *path, const char **dirs, Hashmap *known_features) {
        assert(t);

        ConfigTableItem table[] = {
                { "Transfer",    "MinVersion",              config_parse_min_version,          0, &t->min_version             },
                { "Transfer",    "ProtectVersion",          config_parse_protect_version,      0, &t->protected_versions      },
                { "Transfer",    "Verify",                  config_parse_bool,                 0, &t->verify                  },
                { "Transfer",    "ChangeLog",               config_parse_url_specifiers,       0, &t->changelog               },
                { "Transfer",    "AppStream",               config_parse_url_specifiers,       0, &t->appstream               },
                { "Transfer",    "Features",                config_parse_strv,                 0, &t->features                },
                { "Transfer",    "RequisiteFeatures",       config_parse_strv,                 0, &t->requisite_features      },
                { "Source",      "Type",                    config_parse_resource_type,        0, &t->source.type             },
                { "Source",      "Path",                    config_parse_resource_path,        0, &t->source                  },
                { "Source",      "PathRelativeTo",          config_parse_resource_path_relto,  0, &t->source.path_relative_to },
                { "Source",      "MatchPattern",            config_parse_resource_pattern,     0, &t->source.patterns         },
                { "Target",      "Type",                    config_parse_resource_type,        0, &t->target.type             },
                { "Target",      "Path",                    config_parse_resource_path,        0, &t->target                  },
                { "Target",      "PathRelativeTo",          config_parse_resource_path_relto,  0, &t->target.path_relative_to },
                { "Target",      "MatchPattern",            config_parse_resource_pattern,     0, &t->target.patterns         },
                { "Target",      "MatchPartitionType",      config_parse_resource_ptype,       0, &t->target                  },
                { "Target",      "PartitionUUID",           config_parse_partition_uuid,       0, t                           },
                { "Target",      "PartitionFlags",          config_parse_partition_flags,      0, t                           },
                { "Target",      "PartitionNoAuto",         config_parse_tristate,             0, &t->no_auto                 },
                { "Target",      "PartitionGrowFileSystem", config_parse_tristate,             0, &t->growfs                  },
                { "Target",      "ReadOnly",                config_parse_tristate,             0, &t->read_only               },
                { "Target",      "Mode",                    config_parse_mode,                 0, &t->mode                    },
                { "Target",      "TriesLeft",               config_parse_uint64,               0, &t->tries_left              },
                { "Target",      "TriesDone",               config_parse_uint64,               0, &t->tries_done              },
                { "Target",      "InstancesMax",            config_parse_instances_max,        0, &t->instances_max           },
                { "Target",      "RemoveTemporary",         config_parse_bool,                 0, &t->remove_temporary        },
                { "Target",      "CurrentSymlink",          config_parse_current_symlink,      0, &t->current_symlink         },
                {}
        };

        _cleanup_free_ char *filename = NULL;
        char *e;
        int r;

        assert(path);
        assert(dirs);

        r = path_extract_filename(path, &filename);
        if (r < 0)
                return log_error_errno(r, "Failed to extract filename from path '%s': %m", path);

        r = config_parse_many_full(
                        STRV_MAKE_CONST(path),
                        dirs,
                        strjoina(filename, ".d"),
                        arg_root,
                        /* root_fd= */ -EBADF,
                        "Transfer\0"
                        "Source\0"
                        "Target\0",
                        config_item_table_lookup, table,
                        CONFIG_PARSE_WARN,
                        /* userdata= */ NULL,
                        /* stats_by_path= */ NULL,
                        /* drop_in_files= */ NULL);
        if (r < 0)
                return r;

        e = ASSERT_PTR(endswith(filename, ".transfer") ?: endswith(filename, ".conf"));
        *e = 0; /* Remove the file extension */
        t->id = TAKE_PTR(filename);

        t->enabled = transfer_decide_if_enabled(t, known_features);

        if (!RESOURCE_IS_SOURCE(t->source.type))
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "Source Type= must be one of url-file, url-tar, tar, regular-file, directory, subvolume.");

        if (t->target.type < 0) {
                switch (t->source.type) {

                case RESOURCE_URL_FILE:
                case RESOURCE_REGULAR_FILE:
                        t->target.type =
                                t->target.path && path_startswith(t->target.path, "/dev/") ?
                                RESOURCE_PARTITION : RESOURCE_REGULAR_FILE;
                        break;

                case RESOURCE_URL_TAR:
                case RESOURCE_TAR:
                case RESOURCE_DIRECTORY:
                        t->target.type = RESOURCE_DIRECTORY;
                        break;

                case RESOURCE_SUBVOLUME:
                        t->target.type = RESOURCE_SUBVOLUME;
                        break;

                default:
                        assert_not_reached();
                }
        }

        if (!RESOURCE_IS_TARGET(t->target.type))
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "Target Type= must be one of partition, regular-file, directory, subvolume.");

        if ((IN_SET(t->source.type, RESOURCE_URL_FILE, RESOURCE_PARTITION, RESOURCE_REGULAR_FILE) &&
             !IN_SET(t->target.type, RESOURCE_PARTITION, RESOURCE_REGULAR_FILE)) ||
            (IN_SET(t->source.type, RESOURCE_URL_TAR, RESOURCE_TAR, RESOURCE_DIRECTORY, RESOURCE_SUBVOLUME) &&
             !IN_SET(t->target.type, RESOURCE_DIRECTORY, RESOURCE_SUBVOLUME)))
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "Target type '%s' is incompatible with source type '%s', refusing.",
                                  resource_type_to_string(t->target.type), resource_type_to_string(t->source.type));

        if (!t->source.path && !t->source.path_auto)
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "Source specification lacks Path=.");

        if (t->source.path_relative_to == PATH_RELATIVE_TO_EXPLICIT && !arg_transfer_source)
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "PathRelativeTo=explicit requires --transfer-source= to be specified.");

        if (t->target.path_relative_to == PATH_RELATIVE_TO_EXPLICIT)
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "PathRelativeTo=explicit can only be used in source specifications.");

        if (t->source.path) {
                if (RESOURCE_IS_FILESYSTEM(t->source.type) || t->source.type == RESOURCE_PARTITION)
                        if (!path_is_absolute(t->source.path) || !path_is_normalized(t->source.path))
                                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                                  "Source path is not a normalized, absolute path: %s", t->source.path);

                /* We unofficially support file:// in addition to http:// and https:// for url
                 * sources. That's mostly for testing, since it relieves us from having to set up a HTTP
                 * server, and CURL abstracts this away from us thankfully. */
                if (RESOURCE_IS_URL(t->source.type))
                        if (!http_url_is_valid(t->source.path) && !file_url_is_valid(t->source.path))
                                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                                  "Source path is not a valid HTTP or HTTPS URL: %s", t->source.path);
        }

        if (strv_isempty(t->source.patterns))
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "Source specification lacks MatchPattern=.");

        if (!t->target.path && !t->target.path_auto)
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "Target specification lacks Path= field.");

        if (t->target.path &&
            (!path_is_absolute(t->target.path) || !path_is_normalized(t->target.path)))
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "Target path is not a normalized, absolute path: %s", t->target.path);

        if (strv_isempty(t->target.patterns)) {
                log_syntax(NULL, LOG_INFO, path, 1, 0, "Target specification lacks MatchPattern= expression. Assuming same value as in source specification.");
                strv_free(t->target.patterns);
                t->target.patterns = strv_copy(t->source.patterns);
                if (!t->target.patterns)
                        return log_oom();
        }

        if (t->current_symlink && !RESOURCE_IS_FILESYSTEM(t->target.type) && !path_is_absolute(t->current_symlink))
                return log_syntax(NULL, LOG_ERR, path, 1, SYNTHETIC_ERRNO(EINVAL),
                                  "Current symlink must be absolute path if target is partition: %s", t->current_symlink);

        /* When no instance limit is set, use all available partition slots in case of partitions, or 3 in case of fs objects */
        if (t->instances_max == 0)
                t->instances_max = t->target.type == RESOURCE_PARTITION ? UINT64_MAX : DEFAULT_FILE_INSTANCES_MAX;

        return 0;
}

int transfer_resolve_paths(
                Transfer *t,
                const char *root,
                const char *node) {

        int r;

        /* If Path=auto is used in [Source] or [Target] sections, let's automatically detect the path of the
         * block device to use. Moreover, if this path points to a directory but we need a block device,
         * automatically determine the backing block device, so that users can reference block devices by
         * mount point. */

        assert(t);

        r = resource_resolve_path(&t->source, root, arg_transfer_source, node);
        if (r < 0)
                return r;

        r = resource_resolve_path(&t->target, root, /* relative_to_directory= */ NULL, node);
        if (r < 0)
                return r;

        return 0;
}

static void transfer_remove_temporary(Transfer *t) {
        _cleanup_closedir_ DIR *d = NULL;
        int r;

        assert(t);

        if (!t->remove_temporary)
                return;

        if (!IN_SET(t->target.type, RESOURCE_REGULAR_FILE, RESOURCE_DIRECTORY, RESOURCE_SUBVOLUME))
                return;

        /* Removes all temporary files/dirs from previous runs in the target directory, i.e. all those starting with '.#' */

        d = opendir(t->target.path);
        if (!d) {
                if (errno == ENOENT)
                        return;

                log_debug_errno(errno, "Failed to open target directory '%s', ignoring: %m", t->target.path);
                return;
        }

        for (;;) {
                struct dirent *de;

                errno = 0;
                de = readdir_no_dot(d);
                if (!de) {
                        if (errno != 0)
                                log_debug_errno(errno, "Failed to read target directory '%s', ignoring: %m", t->target.path);
                        break;
                }

                if (!startswith(de->d_name, ".#"))
                        continue;

                r = rm_rf_child(dirfd(d), de->d_name, REMOVE_PHYSICAL|REMOVE_SUBVOLUME|REMOVE_CHMOD);
                if (r == -ENOENT)
                        continue;
                if (r < 0) {
                        log_warning_errno(r, "Failed to remove temporary resource instance '%s/%s', ignoring: %m", t->target.path, de->d_name);
                        continue;
                }

                log_debug("Removed temporary resource instance '%s/%s'.", t->target.path, de->d_name);
        }
}

static int transfer_instance_vacuum(
                Transfer *t,
                Instance *instance) {
        int r;

        assert(t);
        assert(instance);

        switch (t->target.type) {

        case RESOURCE_REGULAR_FILE:
        case RESOURCE_DIRECTORY:
        case RESOURCE_SUBVOLUME:
                r = rm_rf(instance->path, REMOVE_ROOT|REMOVE_PHYSICAL|REMOVE_SUBVOLUME|REMOVE_MISSING_OK|REMOVE_CHMOD);
                if (r < 0 && r != -ENOENT)
                        return log_error_errno(r, "Failed to make room, deleting '%s' failed: %m", instance->path);

                (void) rmdir_parents(instance->path, t->target.path);

                break;

        case RESOURCE_PARTITION: {
                PartitionInfo pinfo = instance->partition_info;
                PartitionChange change = PARTITION_LABEL;

                /* label "_empty" means "no contents" for our purposes */
                pinfo.label = (char*) "_empty";

                /* If the partition had a derived partial/pending type UUID, restore the original
                 * partition type so that the slot is properly recognized as empty in subsequent
                 * scans. */
                if ((instance->is_partial || instance->is_pending) && t->target.partition_type_set) {
                        pinfo.type = t->target.partition_type.uuid;
                        change |= PARTITION_TYPE;
                }

                log_debug("Resetting partition '%s' to empty.", pinfo.device);
                r = patch_partition(t->target.path, &pinfo, change);
                if (r < 0)
                        return r;

                t->target.n_empty++;
                break;
        }

        default:
                assert_not_reached();
        }

        return 0;
}

int transfer_vacuum(
                Transfer *t,
                uint64_t space,
                const char *extra_protected_version) {

        uint64_t instances_max, limit;
        int r, count = 0;

        assert(t);

        transfer_remove_temporary(t);

        /* First, remove any partial or pending instances (unless protected) */
        for (size_t i = 0; i < t->target.n_instances;) {
                Instance *instance = t->target.instances[i];

                assert(instance);

                if (!instance->is_pending && !instance->is_partial) {
                        i++;
                        continue;
                }

                /* If this is listed among the protected versions, then let's not remove it */
                if (strv_contains(t->protected_versions, instance->metadata.version) ||
                    (extra_protected_version && streq(extra_protected_version, instance->metadata.version))) {
                        log_debug("Version '%s' is pending/partial but protected, not removing.", instance->metadata.version);
                        i++;
                        continue;
                }

                assert(instance->resource);

                log_info("%s Removing old %s '%s' (%s).",
                         glyph(GLYPH_RECYCLING),
                         instance->is_partial ? "partial" : "pending",
                         instance->path,
                         resource_type_to_string(instance->resource->type));

                r = transfer_instance_vacuum(t, instance);
                if (r < 0)
                        return 0;

                instance_free(instance);
                memmove(t->target.instances + i, t->target.instances + i + 1, (t->target.n_instances - i - 1) * sizeof(Instance*));
                t->target.n_instances--;

                count++;
        }

        /* Second, calculate how many instances to keep, based on the instance limit — but keep at least one */

        instances_max = arg_instances_max != UINT64_MAX ? arg_instances_max : t->instances_max;
        assert(instances_max >= 1);
        if (instances_max == UINT64_MAX) /* Keep infinite instances? */
                limit = UINT64_MAX;
        else if (space == UINT64_MAX) /* forcibly delete all instances? */
                limit = 0;
        else if (space > instances_max)
                return log_error_errno(SYNTHETIC_ERRNO(ENOSPC),
                                       "Asked to delete more instances than total maximum allowed number of instances, refusing.");
        else if (space == instances_max)
                return log_error_errno(SYNTHETIC_ERRNO(ENOSPC),
                                       "Asked to delete all possible instances, can't allow that. One instance must always remain.");
        else
                limit = instances_max - space;

        if (t->target.type == RESOURCE_PARTITION && space != UINT64_MAX) {
                _cleanup_free_ char *patterns = NULL;
                uint64_t rm, remain;

                patterns = strv_join(t->target.patterns, "|");
                if (!patterns)
                        (void) log_oom_debug();

                /* If we are looking at a partition table, we also have to take into account how many
                 * partition slots of the right type are available */

                if (t->target.n_empty + t->target.n_instances < 2)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOSPC),
                                               "Partition table has less than two partition slots of the right type " SD_ID128_UUID_FORMAT_STR " (%s)%s%s%s, refusing.",
                                               SD_ID128_FORMAT_VAL(t->target.partition_type.uuid),
                                               gpt_partition_type_uuid_to_string(t->target.partition_type.uuid),
                                               !isempty(patterns) ? " and matching the expected pattern '" : "",
                                               strempty(patterns),
                                               !isempty(patterns) ? "'" : "");
                if (space > t->target.n_empty + t->target.n_instances)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOSPC),
                                               "Partition table does not have enough partition slots of right type " SD_ID128_UUID_FORMAT_STR " (%s)%s%s%s for operation.",
                                               SD_ID128_FORMAT_VAL(t->target.partition_type.uuid),
                                               gpt_partition_type_uuid_to_string(t->target.partition_type.uuid),
                                               !isempty(patterns) ? " and matching the expected pattern '" : "",
                                               strempty(patterns),
                                               !isempty(patterns) ? "'" : "");
                if (space == t->target.n_empty + t->target.n_instances)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOSPC),
                                               "Asked to empty all partition table slots of the right type " SD_ID128_UUID_FORMAT_STR " (%s), can't allow that. One instance must always remain.",
                                               SD_ID128_FORMAT_VAL(t->target.partition_type.uuid),
                                               gpt_partition_type_uuid_to_string(t->target.partition_type.uuid));

                rm = LESS_BY(space, t->target.n_empty);
                remain = LESS_BY(t->target.n_instances, rm);
                limit = MIN(limit, remain);
        }

        while (t->target.n_instances > limit) {
                Instance *oldest;
                size_t p = t->target.n_instances - 1;

                for (;;) {
                        oldest = t->target.instances[p];
                        assert(oldest);

                        /* If this is listed among the protected versions, then let's not remove it */
                        if (!strv_contains(t->protected_versions, oldest->metadata.version) &&
                            (!extra_protected_version || !streq(extra_protected_version, oldest->metadata.version)))
                                break;

                        log_debug("Version '%s' is protected, not removing.", oldest->metadata.version);
                        if (p == 0) {
                                oldest = NULL;
                                break;
                        }

                        p--;
                }

                if (!oldest) /* Nothing more to remove */
                        break;

                assert(oldest->resource);

                log_info("%s Removing %s '%s' (%s).",
                         glyph(GLYPH_RECYCLING),
                         space == UINT64_MAX ? "disabled" : "old",
                         oldest->path,
                         resource_type_to_string(oldest->resource->type));

                r = transfer_instance_vacuum(t, oldest);
                if (r < 0)
                        return 0;

                instance_free(oldest);
                memmove(t->target.instances + p, t->target.instances + p + 1, (t->target.n_instances - p - 1) * sizeof(Instance*));
                t->target.n_instances--;

                count++;
        }

        return count;
}

static void compile_pattern_fields(
                const Transfer *t,
                const Instance *i,
                InstanceMetadata *ret) {

        assert(t);
        assert(i);
        assert(ret);

        *ret = (InstanceMetadata) {
                .version = i->metadata.version,

                /* We generally prefer explicitly configured values for the transfer over those automatically
                 * derived from the source instance. Also, if the source is a tar archive, then let's not
                 * patch mtime/mode and use the one embedded in the tar file */
                .partition_uuid = t->partition_uuid_set ? t->partition_uuid : i->metadata.partition_uuid,
                .partition_uuid_set = t->partition_uuid_set || i->metadata.partition_uuid_set,
                .partition_flags = t->partition_flags_set ? t->partition_flags : i->metadata.partition_flags,
                .partition_flags_set = t->partition_flags_set || i->metadata.partition_flags_set,
                .mtime = RESOURCE_IS_TAR(i->resource->type) ? USEC_INFINITY : i->metadata.mtime,
                .mode = t->mode != MODE_INVALID ? t->mode : (RESOURCE_IS_TAR(i->resource->type) ? MODE_INVALID : i->metadata.mode),
                .size = i->metadata.size,
                .tries_done = t->tries_done != UINT64_MAX ? t->tries_done :
                              i->metadata.tries_done != UINT64_MAX ? i->metadata.tries_done : 0,
                .tries_left = t->tries_left != UINT64_MAX ? t->tries_left :
                              i->metadata.tries_left != UINT64_MAX ? i->metadata.tries_left : 3,
                .no_auto = t->no_auto >= 0 ? t->no_auto : i->metadata.no_auto,
                .read_only = t->read_only >= 0 ? t->read_only : i->metadata.read_only,
                .growfs = t->growfs >= 0 ? t->growfs : i->metadata.growfs,
                .sha256sum_set = i->metadata.sha256sum_set,
        };

        memcpy(ret->sha256sum, i->metadata.sha256sum, sizeof(ret->sha256sum));
}

typedef struct CalloutContext {
        const Transfer *transfer;
        const Instance *instance;
        TransferProgress callback;
        PidRef pid;
        const char *name;
        int helper_errno;
        void* userdata;
} CalloutContext;

static CalloutContext *callout_context_free(CalloutContext *ctx) {
        if (!ctx)
                return NULL;

        /* We don't own any data but need to clean up the job pid */
        pidref_done(&ctx->pid);

        return mfree(ctx);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(CalloutContext*, callout_context_free);

static int callout_context_new(const Transfer *t, const Instance *i, TransferProgress cb,
                               const char *name, void* userdata, CalloutContext **ret) {
        _cleanup_(callout_context_freep) CalloutContext *ctx = NULL;

        assert(t);
        assert(i);
        assert(cb);

        ctx = new(CalloutContext, 1);
        if (!ctx)
                return -ENOMEM;

        *ctx = (CalloutContext) {
                .transfer = t,
                .instance = i,
                .callback = cb,
                .pid = PIDREF_NULL,
                .name = name,
                .userdata = userdata,
        };

        *ret = TAKE_PTR(ctx);
        return 0;
}

static int helper_on_exit(sd_event_source *s, const siginfo_t *si, void *userdata) {
        CalloutContext *ctx = ASSERT_PTR(userdata);
        int r;

        assert(s);
        assert(si);
        assert(ctx);

        if (si->si_code == CLD_EXITED) {
                if (si->si_status == EXIT_SUCCESS) {
                        r = 0;
                        log_debug("%s succeeded.", ctx->name);
                } else if (ctx->helper_errno != 0) {
                        r = -ctx->helper_errno;
                        log_error_errno(r, "%s failed with exit status %i: %m", ctx->name, si->si_status);
                } else {
                        r = -EPROTO;
                        log_error("%s failed with exit status %i.", ctx->name, si->si_status);
                }
        } else {
                r = -EPROTO;
                if (IN_SET(si->si_code, CLD_KILLED, CLD_DUMPED))
                        log_error("%s terminated by signal %s.", ctx->name, signal_to_string(si->si_status));
                else
                        log_error("%s failed due to unknown reason.", ctx->name);
        }

        return sd_event_exit(sd_event_source_get_event(s), r);
}

static int helper_on_notify(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        CalloutContext *ctx = ASSERT_PTR(userdata);
        int r;

        assert(fd >= 0);

        _cleanup_free_ char *buf = NULL;
        _cleanup_(pidref_done) PidRef sender_pid = PIDREF_NULL;
        r = notify_recv(fd, &buf, /* ret_ucred= */ NULL, &sender_pid);
        if (r == -EAGAIN)
                return 0;
        if (r < 0)
                return r;

        if (!pidref_equal(&ctx->pid, &sender_pid)) {
                log_warning("Got notification datagram from unexpected peer, ignoring.");
                return 0;
        }

        char *errno_str = find_line_startswith(buf, "ERRNO=");
        if (errno_str) {
                truncate_nl(errno_str);
                r = parse_errno(errno_str);
                if (r < 0)
                        log_warning_errno(r, "Got invalid errno value '%s', ignoring: %m", errno_str);
                else {
                        ctx->helper_errno = r;
                        log_debug_errno(r, "Got errno from callout: %i (%m)", r);
                }
        }

        char *progress_str = find_line_startswith(buf, "X_IMPORT_PROGRESS=");
        if (progress_str) {
                truncate_nl(progress_str);

                int progress = parse_percent(progress_str);
                if (progress < 0)
                        log_warning("Got invalid percent value '%s', ignoring.", progress_str);
                else {
                        r = ctx->callback(ctx->transfer, ctx->instance, progress);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

static int run_callout(
                const char *name,
                char *cmdline[],
                const Transfer *transfer,
                const Instance *instance,
                TransferProgress callback,
                void *userdata) {

        int r;

        assert(name);
        assert(cmdline);
        assert(cmdline[0]);

        _cleanup_(callout_context_freep) CalloutContext *ctx = NULL;
        r = callout_context_new(transfer, instance, callback, name, userdata, &ctx);
        if (r < 0)
                return log_oom();

        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        r = sd_event_new(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to create event: %m");

        /* Kill the helper & return an error if we get interrupted by a signal */
        r = sd_event_add_signal(event, NULL, SIGINT | SD_EVENT_SIGNAL_PROCMASK, NULL, INT_TO_PTR(-ECANCELED));
        if (r < 0)
                return log_error_errno(r, "Failed to register signal to event: %m");
        r = sd_event_add_signal(event, NULL, SIGTERM | SD_EVENT_SIGNAL_PROCMASK, NULL, INT_TO_PTR(-ECANCELED));
        if (r < 0)
                return log_error_errno(r, "Failed to register signal to event: %m");

        _cleanup_free_ char *bind_name = NULL;
        r = notify_socket_prepare(
                        event,
                        SD_EVENT_PRIORITY_NORMAL - 5,
                        helper_on_notify,
                        ctx,
                        &bind_name);
        if (r < 0)
                return log_error_errno(r, "Failed to prepare notify socket: %m");

        r = pidref_safe_fork(ctx->name, FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_LOG, &ctx->pid);
        if (r < 0)
                return log_error_errno(r, "Failed to fork process %s: %m", ctx->name);
        if (r == 0) {
                /* Child */
                if (setenv("NOTIFY_SOCKET", bind_name, 1) < 0) {
                        log_error_errno(errno, "setenv() failed: %m");
                        _exit(EXIT_FAILURE);
                }
                r = invoke_callout_binary(cmdline[0], (char *const*) cmdline);
                log_error_errno(r, "Failed to execute %s tool: %m", cmdline[0]);
                _exit(EXIT_FAILURE);
        }

        /* Quit the loop w/ when child process exits */
        _cleanup_(sd_event_source_unrefp) sd_event_source *exit_source = NULL;
        r = event_add_child_pidref(event, &exit_source, &ctx->pid, WEXITED, helper_on_exit, ctx);
        if (r < 0)
                return log_error_errno(r, "Failed to add child process to event loop: %m");

        r = sd_event_source_set_child_process_own(exit_source, true);
        if (r < 0)
                return log_error_errno(r, "Failed to take ownership of child process: %m");

        /* Process events until the helper quits */
        return sd_event_loop(event);
}

/* Build the filenames and paths which is normally done by transfer_acquire_instance(), but for partial
 * and pending instances which are about to be installed (in which case, transfer_acquire_instance() is
 * skipped). */
int transfer_compute_temporary_paths(Transfer *t, Instance *i, InstanceMetadata *f) {
        _cleanup_free_ char *formatted_pattern = NULL;
        int r;

        assert(t);
        assert(i);

        assert(!t->final_path);
        assert(!t->temporary_partial_path);
        assert(!t->temporary_pending_path);
        assert(!t->final_partition_label);
        assert(!strv_isempty(t->target.patterns));

        /* Format the target name using the first pattern specified */
        compile_pattern_fields(t, i, f);
        r = pattern_format(t->target.patterns[0], f, &formatted_pattern);
        if (r < 0)
                return log_error_errno(r, "Failed to format target pattern: %m");

        if (RESOURCE_IS_FILESYSTEM(t->target.type)) {
                _cleanup_free_ char *final_dir = NULL, *final_filename = NULL, *partial_filename = NULL, *pending_filename = NULL;

                if (!path_is_safe(formatted_pattern))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Formatted pattern is not suitable as file name, refusing: %s", formatted_pattern);

                t->final_path = path_join(t->target.path, formatted_pattern);
                if (!t->final_path)
                        return log_oom();

                /* Build the paths for the partial and pending files, which hold the resource while it’s
                 * being acquired and after it’s been acquired (but before it’s moved to the final_path
                 * when it’s installed).
                 *
                 * Split the filename off the `final_path`, then add a prefix to it for each of partial and
                 * pending, then join them back on to the same directory. */
                r = path_split_prefix_filename(t->final_path, &final_dir, &final_filename);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse path: %m");

                if (!strprepend(&partial_filename, ".sysupdate.partial.", final_filename))
                        return log_oom();

                if (!strprepend(&pending_filename, ".sysupdate.pending.", final_filename))
                        return log_oom();

                t->temporary_partial_path = path_join(final_dir, partial_filename);
                if (!t->temporary_partial_path)
                        return log_oom();

                t->temporary_pending_path = path_join(final_dir, pending_filename);
                if (!t->temporary_pending_path)
                        return log_oom();
        }

        if (t->target.type == RESOURCE_PARTITION) {
                r = gpt_partition_label_valid(formatted_pattern);
                if (r < 0)
                        return log_error_errno(r, "Failed to determine if formatted pattern is suitable as GPT partition label: %s", formatted_pattern);
                if (!r)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Formatted pattern is not suitable as GPT partition label, refusing: %s", formatted_pattern);

                if (!t->target.partition_type_set)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Partition type must be set for partition targets.");

                /* Derive temporary partition type UUIDs for partial/pending states from the configured
                 * partition type. This avoids the need for label prefixes. */
                r = gpt_partition_type_uuid_for_sysupdate_partial(t->target.partition_type.uuid, &t->partition_type_partial);
                if (r < 0)
                        return log_error_errno(r, "Failed to derive partial partition type UUID: %m");

                r = gpt_partition_type_uuid_for_sysupdate_pending(t->target.partition_type.uuid, &t->partition_type_pending);
                if (r < 0)
                        return log_error_errno(r, "Failed to derive pending partition type UUID: %m");

                t->final_partition_label = TAKE_PTR(formatted_pattern);
        }

        return 0;
}

int transfer_acquire_instance(Transfer *t, Instance *i, InstanceMetadata *f, TransferProgress cb, void *userdata) {
        _cleanup_free_ char *digest = NULL;
        char offset[DECIMAL_STR_MAX(uint64_t)+1], max_size[DECIMAL_STR_MAX(uint64_t)+1];
        const char *where = NULL;
        Instance *existing;
        int r;

        assert(t);
        assert(i);
        assert(f);
        assert(i->resource == &t->source);
        assert(cb);

        /* Does this instance already exist in the target? Then we don't need to acquire anything */
        existing = resource_find_instance(&t->target, i->metadata.version);
        if (existing && (existing->is_partial || existing->is_pending))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to acquire '%s', instance is already partial or pending in the target.", i->path);
        if (existing) {
                log_info("No need to acquire '%s', already installed.", i->path);
                return 0;
        }

        if (RESOURCE_IS_FILESYSTEM(t->target.type)) {
                r = mkdir_parents(t->temporary_partial_path, 0755);
                if (r < 0)
                        return log_error_errno(r, "Cannot create target directory: %m");

                r = mkdir_parents(t->temporary_pending_path, 0755);
                if (r < 0)
                        return log_error_errno(r, "Cannot create target directory: %m");

                r = mkdir_parents(t->final_path, 0755);
                if (r < 0)
                        return log_error_errno(r, "Cannot create target directory: %m");

                where = t->final_path;
        }

        if (t->target.type == RESOURCE_PARTITION) {
                r = find_suitable_partition(
                                t->target.path,
                                i->metadata.size,
                                t->target.partition_type_set ? &t->target.partition_type.uuid : NULL,
                                &t->partition_info);
                if (r < 0)
                        return r;

                xsprintf(offset, "%" PRIu64, t->partition_info.start);
                xsprintf(max_size, "%" PRIu64, t->partition_info.size);

                where = t->partition_info.device;

                /* Set the partition label and change the partition type to the derived "partial" type UUID
                 * to indicate that a transfer to it is in progress. */
                r = free_and_strdup_warn(&t->partition_info.label, t->final_partition_label);
                if (r < 0)
                        return r;
                t->partition_info.type = t->partition_type_partial;
                t->partition_change = PARTITION_LABEL | PARTITION_TYPE;

                log_debug("Marking partition '%s' as partial (label='%s', type=%s).",
                          t->partition_info.device,
                          t->partition_info.label,
                          SD_ID128_TO_UUID_STRING(t->partition_info.type));
                r = patch_partition(
                                t->target.path,
                                &t->partition_info,
                                t->partition_change);
                if (r < 0)
                        return r;
        }

        assert(where);

        log_info("%s Acquiring %s %s %s...", glyph(GLYPH_DOWNLOAD), i->path, glyph(GLYPH_ARROW_RIGHT), where);

        if (RESOURCE_IS_URL(i->resource->type)) {
                /* For URL sources we require the SHA256 sum to be known so that we can validate the
                 * download. */

                if (!i->metadata.sha256sum_set)
                        return log_error_errno(r, "SHA256 checksum not known for download '%s', refusing.", i->path);

                digest = hexmem(i->metadata.sha256sum, sizeof(i->metadata.sha256sum));
                if (!digest)
                        return log_oom();
        }

        switch (i->resource->type) { /* Source */

        case RESOURCE_REGULAR_FILE:

                switch (t->target.type) { /* Target */

                case RESOURCE_REGULAR_FILE:

                        /* regular file → regular file (why fork off systemd-import for such a simple file
                         * copy case? implicit decompression mostly, and thus also sandboxing. Also, the
                         * importer has some tricks up its sleeve, such as sparse file generation, which we
                         * want to take benefit of, too.) */

                        r = run_callout("(sd-import-raw)",
                                        STRV_MAKE(
                                               SYSTEMD_IMPORT_PATH,
                                               "raw",
                                               "--direct",          /* just copy/unpack the specified file, don't do anything else */
                                               arg_sync ? "--sync=yes" : "--sync=no",
                                               i->path,
                                               t->temporary_partial_path),
                                        t, i, cb, userdata);
                        break;

                case RESOURCE_PARTITION:

                        /* regular file → partition */

                        r = run_callout("(sd-import-raw)",
                                        STRV_MAKE(
                                               SYSTEMD_IMPORT_PATH,
                                               "raw",
                                               "--direct",          /* just copy/unpack the specified file, don't do anything else */
                                               "--offset", offset,
                                               "--size-max", max_size,
                                               arg_sync ? "--sync=yes" : "--sync=no",
                                               i->path,
                                               t->target.path),
                                        t, i, cb, userdata);
                        break;

                default:
                        assert_not_reached();
                }

                break;

        case RESOURCE_DIRECTORY:
        case RESOURCE_SUBVOLUME:
                assert(IN_SET(t->target.type, RESOURCE_DIRECTORY, RESOURCE_SUBVOLUME));

                /* directory/subvolume → directory/subvolume */

                r = run_callout("(sd-import-fs)",
                                STRV_MAKE(
                                       SYSTEMD_IMPORT_FS_PATH,
                                       "run",
                                       "--direct",          /* just untar the specified file, don't do anything else */
                                       arg_sync ? "--sync=yes" : "--sync=no",
                                       t->target.type == RESOURCE_SUBVOLUME ? "--btrfs-subvol=yes" : "--btrfs-subvol=no",
                                       i->path,
                                       t->temporary_partial_path),
                                t, i, cb, userdata);
                break;

        case RESOURCE_TAR:
                assert(IN_SET(t->target.type, RESOURCE_DIRECTORY, RESOURCE_SUBVOLUME));

                /* tar → directory/subvolume */

                r = run_callout("(sd-import-tar)",
                                STRV_MAKE(
                                       SYSTEMD_IMPORT_PATH,
                                       "tar",
                                       "--direct",          /* just untar the specified file, don't do anything else */
                                       arg_sync ? "--sync=yes" : "--sync=no",
                                       t->target.type == RESOURCE_SUBVOLUME ? "--btrfs-subvol=yes" : "--btrfs-subvol=no",
                                       i->path,
                                       t->temporary_partial_path),
                                t, i, cb, userdata);
                break;

        case RESOURCE_URL_FILE:

                switch (t->target.type) {

                case RESOURCE_REGULAR_FILE:

                        /* url file → regular file */

                        r = run_callout("(sd-pull-raw)",
                                       STRV_MAKE(
                                               SYSTEMD_PULL_PATH,
                                               "raw",
                                               "--direct",          /* just download the specified URL, don't download anything else */
                                               "--verify", digest,  /* validate by explicit SHA256 sum */
                                               arg_sync ? "--sync=yes" : "--sync=no",
                                               i->path,
                                               t->temporary_partial_path),
                                        t, i, cb, userdata);
                        break;

                case RESOURCE_PARTITION:

                        /* url file → partition */

                        r = run_callout("(sd-pull-raw)",
                                        STRV_MAKE(
                                               SYSTEMD_PULL_PATH,
                                               "raw",
                                               "--direct",              /* just download the specified URL, don't download anything else */
                                               "--verify", digest,      /* validate by explicit SHA256 sum */
                                               "--offset", offset,
                                               "--size-max", max_size,
                                               arg_sync ? "--sync=yes" : "--sync=no",
                                               i->path,
                                               t->target.path),
                                        t, i, cb, userdata);
                        break;

                default:
                        assert_not_reached();
                }

                break;

        case RESOURCE_URL_TAR:
                assert(IN_SET(t->target.type, RESOURCE_DIRECTORY, RESOURCE_SUBVOLUME));

                r = run_callout("(sd-pull-tar)",
                                STRV_MAKE(
                                       SYSTEMD_PULL_PATH,
                                       "tar",
                                       "--direct",          /* just download the specified URL, don't download anything else */
                                       "--verify", digest,  /* validate by explicit SHA256 sum */
                                       t->target.type == RESOURCE_SUBVOLUME ? "--btrfs-subvol=yes" : "--btrfs-subvol=no",
                                       arg_sync ? "--sync=yes" : "--sync=no",
                                       i->path,
                                       t->temporary_partial_path),
                                t, i, cb, userdata);
                break;

        default:
                assert_not_reached();
        }
        if (r < 0)
                return r;

        if (RESOURCE_IS_FILESYSTEM(t->target.type)) {
                bool need_sync = false;
                assert(t->temporary_partial_path);
                assert(t->temporary_pending_path);

                /* Apply file attributes if set */
                if (f->mtime != USEC_INFINITY) {
                        struct timespec ts;

                        timespec_store(&ts, f->mtime);

                        if (utimensat(AT_FDCWD, t->temporary_partial_path, (struct timespec[2]) { ts, ts }, AT_SYMLINK_NOFOLLOW) < 0)
                                return log_error_errno(errno, "Failed to adjust mtime of '%s': %m", t->temporary_partial_path);

                        need_sync = true;
                }

                if (f->mode != MODE_INVALID) {
                        /* Try with AT_SYMLINK_NOFOLLOW first, because it's the safe thing to do. Older
                         * kernels don't support that however, in that case we fall back to chmod(). Not as
                         * safe, but shouldn't be a problem, given that we don't create symlinks here. */
                        if (fchmodat(AT_FDCWD, t->temporary_partial_path, f->mode, AT_SYMLINK_NOFOLLOW) < 0 &&
                            (!ERRNO_IS_NOT_SUPPORTED(errno) || chmod(t->temporary_partial_path, f->mode) < 0))
                                return log_error_errno(errno, "Failed to adjust mode of '%s': %m", t->temporary_partial_path);

                        need_sync = true;
                }

                /* Synchronize */
                if (arg_sync && need_sync) {
                        if (t->target.type == RESOURCE_REGULAR_FILE)
                                r = fsync_path_and_parent_at(AT_FDCWD, t->temporary_partial_path);
                        else {
                                assert(IN_SET(t->target.type, RESOURCE_DIRECTORY, RESOURCE_SUBVOLUME));
                                r = syncfs_path(AT_FDCWD, t->temporary_partial_path);
                        }
                        if (r < 0)
                                return log_error_errno(r, "Failed to synchronize file system backing '%s': %m", t->temporary_partial_path);
                }

                t->install_read_only = f->read_only;

                /* Rename the file from `.sysupdate.partial.<VERSION>` to `.sysupdate.pending.<VERSION>` to indicate it’s ready to install. */
                log_debug("Renaming resource instance '%s' to '%s'.", t->temporary_partial_path, t->temporary_pending_path);
                r = install_file(AT_FDCWD, t->temporary_partial_path,
                                 AT_FDCWD, t->temporary_pending_path,
                                 INSTALL_REPLACE|
                                 (t->install_read_only > 0 ? INSTALL_READ_ONLY : 0)|
                                 (t->target.type == RESOURCE_REGULAR_FILE ? INSTALL_FSYNC_FULL : INSTALL_SYNCFS));
                if (r < 0)
                        return log_error_errno(r, "Failed to move '%s' into pending place: %m", t->temporary_pending_path);
        }

        if (t->target.type == RESOURCE_PARTITION) {
                /* Now change the partition type to the derived "pending" type UUID to indicate that the
                 * acquire is complete and the partition is ready for install. */
                t->partition_info.type = t->partition_type_pending;
                t->partition_change = PARTITION_TYPE;

                if (f->partition_uuid_set) {
                        t->partition_info.uuid = f->partition_uuid;
                        t->partition_change |= PARTITION_UUID;
                }

                if (f->partition_flags_set) {
                        t->partition_info.flags = f->partition_flags;
                        t->partition_change |= PARTITION_FLAGS;
                }

                if (f->no_auto >= 0) {
                        t->partition_info.no_auto = f->no_auto;
                        t->partition_change |= PARTITION_NO_AUTO;
                }

                if (f->read_only >= 0) {
                        t->partition_info.read_only = f->read_only;
                        t->partition_change |= PARTITION_READ_ONLY;
                }

                if (f->growfs >= 0) {
                        t->partition_info.growfs = f->growfs;
                        t->partition_change |= PARTITION_GROWFS;
                }

                log_debug("Marking partition '%s' as pending (type=%s).",
                          t->partition_info.device,
                          SD_ID128_TO_UUID_STRING(t->partition_info.type));
                r = patch_partition(
                                t->target.path,
                                &t->partition_info,
                                t->partition_change);
                if (r < 0)
                        return r;
        }

        /* For regular file cases the only step left is to install the file in place, which install_file()
         * will do via rename(). For partition cases the only step left is to update the partition table,
         * which is done at the same place. */

        log_info("Successfully acquired '%s'.", i->path);
        return 0;
}

int transfer_process_partial_and_pending_instance(Transfer *t, Instance *i) {
        InstanceMetadata f;
        Instance *existing;
        int r;

        assert(t);
        assert(i);

        log_debug("transfer_process_partial_and_pending_instance %s", i->path);

        /* Does this instance already exist in the target but isn’t pending? */
        existing = resource_find_instance(&t->target, i->metadata.version);
        if (existing && !existing->is_pending)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to acquire '%s', instance is already in the target but is not pending.", i->path);

        /* All we need to do is compute the temporary paths. We don’t need to do any of the other work in
         * transfer_acquire_instance(). */
        r = transfer_compute_temporary_paths(t, i, &f);
        if (r < 0)
                return r;

        /* This is the analogue of find_suitable_partition(), but since finding the suitable partition has
         * already happened in the acquire phase, the target should already have that information and it
         * should already have been claimed with the pending partition type UUID. */
        if (t->target.type == RESOURCE_PARTITION) {
                assert(i->resource == &t->target);
                assert(i->is_pending);

                r = partition_info_copy(&t->partition_info, &i->partition_info);
                if (r < 0)
                        return r;
        }

        return 0;
}

int transfer_install_instance(
                Transfer *t,
                Instance *i,
                const char *root) {

        int r;

        assert(t);
        assert(i);
        assert(i->resource);
        assert(i->is_pending || t == container_of(i->resource, Transfer, source));

        log_debug("transfer_install_instance %s %s %s %d", i->path, t->temporary_pending_path, t->final_partition_label, t->partition_change);

        if (t->temporary_pending_path) {
                assert(RESOURCE_IS_FILESYSTEM(t->target.type));
                assert(t->final_path);

                r = install_file(AT_FDCWD, t->temporary_pending_path,
                                 AT_FDCWD, t->final_path,
                                 INSTALL_REPLACE|
                                 (t->install_read_only > 0 ? INSTALL_READ_ONLY : 0)|
                                 (t->target.type == RESOURCE_REGULAR_FILE ? INSTALL_FSYNC_FULL : INSTALL_SYNCFS));
                if (r < 0)
                        return log_error_errno(r, "Failed to move '%s' into place: %m", t->final_path);

                log_info("Successfully installed '%s' (%s) as '%s' (%s).",
                         i->path,
                         resource_type_to_string(i->resource->type),
                         t->final_path,
                         resource_type_to_string(t->target.type));

                t->temporary_pending_path = mfree(t->temporary_pending_path);
        }

        if (t->final_partition_label) {
                assert(t->target.type == RESOURCE_PARTITION);
                assert(t->target.partition_type_set);

                r = free_and_strdup_warn(&t->partition_info.label, t->final_partition_label);
                if (r < 0)
                        return r;

                /* Restore the original partition type UUID now that the partition is fully installed. */
                t->partition_info.type = t->target.partition_type.uuid;
                t->partition_change = PARTITION_LABEL | PARTITION_TYPE;

                r = patch_partition(
                                t->target.path,
                                &t->partition_info,
                                t->partition_change);
                if (r < 0)
                        return r;

                log_info("Successfully installed '%s' (%s) as '%s' (%s).",
                         i->path,
                         resource_type_to_string(i->resource->type),
                         t->partition_info.device,
                         resource_type_to_string(t->target.type));
        }

        if (t->current_symlink) {
                _cleanup_free_ char *buf = NULL, *parent = NULL, *relative = NULL, *resolved = NULL;
                const char *link_path, *link_target;
                bool resolve_link_path = false;

                if (RESOURCE_IS_FILESYSTEM(t->target.type)) {

                        assert(t->target.path);

                        if (path_is_absolute(t->current_symlink)) {
                                link_path = t->current_symlink;
                                resolve_link_path = true;
                        } else {
                                buf = path_make_absolute(t->current_symlink, t->target.path);
                                if (!buf)
                                        return log_oom();

                                link_path = buf;
                        }

                        link_target = t->final_path;

                } else if (t->target.type == RESOURCE_PARTITION) {

                        assert(path_is_absolute(t->current_symlink));

                        link_path = t->current_symlink;
                        link_target = t->partition_info.device;

                        resolve_link_path = true;
                } else
                        assert_not_reached();

                if (resolve_link_path && root) {
                        r = chase(link_path, root, CHASE_PREFIX_ROOT|CHASE_NONEXISTENT|CHASE_TRIGGER_AUTOFS, &resolved, NULL);
                        if (r < 0)
                                return log_error_errno(r, "Failed to resolve current symlink path '%s': %m", link_path);

                        link_path = resolved;
                }

                if (link_target) {
                        r = path_extract_directory(link_path, &parent);
                        if (r < 0)
                                return log_error_errno(r, "Failed to extract directory of target path '%s': %m", link_path);

                        r = path_make_relative(parent, link_target, &relative);
                        if (r < 0)
                                return log_error_errno(r, "Failed to make symlink path '%s' relative to '%s': %m", link_target, parent);

                        r = symlink_atomic(relative, link_path);
                        if (r < 0)
                                return log_error_errno(r, "Failed to update current symlink '%s' %s '%s': %m",
                                                       link_path,
                                                       glyph(GLYPH_ARROW_RIGHT),
                                                       relative);

                        log_info("Updated symlink '%s' %s '%s'.",
                                 link_path, glyph(GLYPH_ARROW_RIGHT), relative);
                }
        }

        return 0;
}
