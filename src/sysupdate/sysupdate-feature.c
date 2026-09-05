/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-json.h"

#include "alloc-util.h"
#include "condition.h"
#include "conf-parser.h"
#include "hash-funcs.h"
#include "json-util.h"
#include "path-util.h"
#include "string-util.h"
#include "sysupdate-config.h"
#include "sysupdate-feature.h"
#include "sysupdate-util.h"

static Feature *feature_free(Feature *f) {
        if (!f)
                return NULL;

        free(f->id);

        free(f->description);
        free(f->documentation);
        free(f->appstream);

        condition_free_list(f->suggest_on);

        return mfree(f);
}

Feature *feature_new(void) {
        Feature *f;

        f = new(Feature, 1);
        if (!f)
                return NULL;

        *f = (Feature) {
                .n_ref = 1,
                .suggest = -1,
        };

        return f;
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(Feature, feature, feature_free);

DEFINE_HASH_OPS_WITH_VALUE_DESTRUCTOR(feature_hash_ops,
                                      char, string_hash_func, string_compare_func,
                                      Feature, feature_unref);

int feature_read_definition(Feature *f, const char *root, const char *path, const char *const *dirs) {
        int r;

        assert(f);
        assert(path);
        assert(dirs);

        _cleanup_free_ char *filename = NULL;
        r = path_extract_filename(path, &filename);
        if (r < 0)
                return log_error_errno(r, "Failed to extract filename from path '%s': %m", path);

        char *e = endswith(filename, ".feature");
        if (!e)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Feature file has bad suffix: %s", filename);

        _cleanup_free_ char *id = strndup(filename, e - filename);
        if (!id)
                return log_oom();

        if (!feature_name_valid(id))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Malformed feature filename '%s': %m", filename);

        ConfigTableItem table[] = {
                { "Feature", "Description",                config_parse_string,         0,                             &f->description   },
                { "Feature", "Documentation",              config_parse_url_specifiers, 0,                             &f->documentation },
                { "Feature", "AppStream",                  config_parse_url_specifiers, 0,                             &f->appstream     },
                { "Feature", "Enabled",                    config_parse_bool,           0,                             &f->enabled       },
                { "Feature", "Suggest",                    config_parse_tristate,       0,                             &f->suggest       },
                { "Feature", "SuggestOnArchitecture",      config_parse_condition,      CONDITION_ARCHITECTURE,        &f->suggest_on    },
                { "Feature", "SuggestOnFirmware",          config_parse_condition,      CONDITION_FIRMWARE,            &f->suggest_on    },
                { "Feature", "SuggestOnVirtualization",    config_parse_condition,      CONDITION_VIRTUALIZATION,      &f->suggest_on    },
                { "Feature", "SuggestOnHost",              config_parse_condition,      CONDITION_HOST,                &f->suggest_on    },
                { "Feature", "SuggestOnFraction",          config_parse_condition,      CONDITION_FRACTION,            &f->suggest_on    },
                { "Feature", "SuggestOnKernelCommandLine", config_parse_condition,      CONDITION_KERNEL_COMMAND_LINE, &f->suggest_on    },
                { "Feature", "SuggestOnVersion",           config_parse_condition,      CONDITION_VERSION,             &f->suggest_on    },
                { "Feature", "SuggestOnCredential",        config_parse_condition,      CONDITION_CREDENTIAL,          &f->suggest_on    },
                { "Feature", "SuggestOnSecurity",          config_parse_condition,      CONDITION_SECURITY,            &f->suggest_on    },
                { "Feature", "SuggestOnOSRelease",         config_parse_condition,      CONDITION_OS_RELEASE,          &f->suggest_on    },
                { "Feature", "SuggestOnMachineTag",        config_parse_condition,      CONDITION_MACHINE_TAG,         &f->suggest_on    },
                {}
        };

        r = config_parse_many_full(
                        STRV_MAKE_CONST(path),
                        dirs,
                        strjoina(filename, ".d"),
                        root,
                        /* root_fd= */ -EBADF,
                        "Feature\0",
                        config_item_table_lookup, table,
                        CONFIG_PARSE_WARN,
                        (void *) root,
                        /* ret_stats_by_path= */ NULL,
                        /* ret_drop_in_files= */ NULL);
        if (r < 0)
                return r;

        f->id = TAKE_PTR(id);

        return 0;
}

static int dispatch_feature_id(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        char **id = ASSERT_PTR(userdata);

        assert(variant);

        if (!sd_json_variant_is_string(variant))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a string.", strna(name));

        if (!feature_name_valid(sd_json_variant_string(variant)))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' is not a valid feature name.", strna(name));

        if (free_and_strdup(id, sd_json_variant_string(variant)) < 0)
                return json_log_oom(variant, flags);

        return 0;
}

int feature_from_json(Feature *f, sd_json_variant *v, const char *origin) {
        int r;

        assert(f);
        assert(origin);

        /* Fills in a feature definition from a JSON object, as acquired from a component provider, the
         * equivalent of feature_read_definition() for .feature files. Note that in contrast to the
         * configuration files no specifier expansion takes place, and no conditions are supported. 'origin'
         * identifies where the data came from, for logging purposes. */

        static const sd_json_dispatch_field dispatch_table[] = {
                { "id",            SD_JSON_VARIANT_STRING,  dispatch_feature_id,       offsetof(Feature, id),            SD_JSON_MANDATORY },
                { "description",   SD_JSON_VARIANT_STRING,  sd_json_dispatch_string,   offsetof(Feature, description),   0 },
                { "documentation", SD_JSON_VARIANT_STRING,  json_dispatch_http_url,    offsetof(Feature, documentation), 0 },
                { "appStream",     SD_JSON_VARIANT_STRING,  json_dispatch_http_url,    offsetof(Feature, appstream),     0 },
                { "enabled",       SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool,  offsetof(Feature, enabled),       0 },
                { "suggest",       SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_tristate, offsetof(Feature, suggest),       0 },
                {},
        };

        r = sd_json_dispatch(v, dispatch_table, SD_JSON_LOG, f);
        if (r < 0)
                return log_error_errno(r, "Failed to parse feature definition from %s: %m", origin);

        return 0;
}

int feature_is_suggested(Feature *f) {
        assert(f);

        if (f->suggest >= 0)
                return f->suggest;

        if (!f->suggest_on) /* no condition → false */
                return false;

        return condition_test_list(f->suggest_on, environ, suggest_on_type_to_string, /* logger= */ NULL, /* userdata= */ NULL);
}
