/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-json.h"

#include "alloc-util.h"
#include "condition.h"
#include "conf-parser.h"
#include "json-util.h"
#include "log.h"
#include "string-util.h"
#include "strv.h"
#include "sysupdate-component.h"
#include "sysupdate-config.h"
#include "sysupdate-util.h"

void component_done(Component *c) {
        assert(c);

        c->description = mfree(c->description);
        c->documentation = strv_free(c->documentation);
        c->suggest_on = condition_free_list(c->suggest_on);
        c->min_version = mfree(c->min_version);
        c->max_version = mfree(c->max_version);
        c->protected_versions = strv_free(c->protected_versions);
}

int component_read_definition(Component *c, const char *name, const char *root) {
        int r;

        assert(c);
        assert(name);

        _cleanup_free_ char *j = strjoin("sysupdate.", name, ".component");
        if (!j)
                return log_oom();

        ConfigTableItem table[] = {
                { "Component", "Description",                config_parse_string,              0,                             &c->description   },
                { "Component", "Documentation",              config_parse_url_specifiers_many, 0,                             &c->documentation },
                { "Component", "Enabled",                    config_parse_tristate,            0,                             &c->enabled       },
                { "Component", "Suggest",                    config_parse_tristate,            0,                             &c->suggest       },
                { "Component", "SuggestOnArchitecture",      config_parse_condition,           CONDITION_ARCHITECTURE,        &c->suggest_on    },
                { "Component", "SuggestOnFirmware",          config_parse_condition,           CONDITION_FIRMWARE,            &c->suggest_on    },
                { "Component", "SuggestOnVirtualization",    config_parse_condition,           CONDITION_VIRTUALIZATION,      &c->suggest_on    },
                { "Component", "SuggestOnHost",              config_parse_condition,           CONDITION_HOST,                &c->suggest_on    },
                { "Component", "SuggestOnFraction",          config_parse_condition,           CONDITION_FRACTION,            &c->suggest_on    },
                { "Component", "SuggestOnKernelCommandLine", config_parse_condition,           CONDITION_KERNEL_COMMAND_LINE, &c->suggest_on    },
                { "Component", "SuggestOnVersion",           config_parse_condition,           CONDITION_VERSION,             &c->suggest_on    },
                { "Component", "SuggestOnCredential",        config_parse_condition,           CONDITION_CREDENTIAL,          &c->suggest_on    },
                { "Component", "SuggestOnSecurity",          config_parse_condition,           CONDITION_SECURITY,            &c->suggest_on    },
                { "Component", "SuggestOnOSRelease",         config_parse_condition,           CONDITION_OS_RELEASE,          &c->suggest_on    },
                { "Component", "SuggestOnMachineTag",        config_parse_condition,           CONDITION_MACHINE_TAG,         &c->suggest_on    },
                { "Component", "MinVersion",                 config_parse_version_bound,       0,                             &c->min_version   },
                { "Component", "MaxVersion",                 config_parse_version_bound,       0,                             &c->max_version   },
                { "Component", "ProtectVersion",             config_parse_protect_version,     0,                             &c->protected_versions },
                {}
        };

        r = config_parse_standard_file_with_dropins_full(
                        root,
                        /* root_fd= */ -EBADF,
                        j,
                        "Component\0",
                        config_item_table_lookup, table,
                        CONFIG_PARSE_WARN,
                        /* userdata= */ (void *) root,
                        /* ret_stats_by_path= */ NULL,
                        /* ret_dropin_files= */ NULL);
        if (r < 0)
                return r;

        return 0;
}

int component_is_suggested(const Component *c) {
        assert(c);

        if (c->suggest >= 0)
                return c->suggest;

        if (!c->suggest_on) /* no condition → false */
                return false;

        return condition_test_list(c->suggest_on, environ, suggest_on_type_to_string, /* logger= */ NULL, /* userdata= */ NULL);
}

int component_to_json(const Component *c, sd_json_variant **ret) {
        int r;

        assert(c);
        assert(ret);

        /* Serializes the component metadata, with the effective enablement and suggestion state. The field
         * names match the settings in sysupdate.components(5). */

        r = component_is_suggested(c);
        if (r < 0)
                return log_error_errno(r, "Failed to determine if component is suggested: %m");

        r = sd_json_buildo(
                        ret,
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("description", c->description),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("documentation", c->documentation),
                        SD_JSON_BUILD_PAIR_BOOLEAN("enabled", c->enabled != 0),
                        SD_JSON_BUILD_PAIR_BOOLEAN("suggest", r > 0),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("minVersion", c->min_version),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("maxVersion", c->max_version),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("protectVersion", c->protected_versions));
        if (r < 0)
                return log_oom();

        return 0;
}

int component_from_json(Component *c, sd_json_variant *v, const char *origin) {
        int r;

        assert(c);
        assert(origin);

        /* The inverse of component_to_json(): fills in the component metadata from a JSON object, as acquired
         * from a component provider, typically a Target object (whose identifier is ignored here). If the
         * object is NULL, all settings take their defaults. Note that in contrast to the configuration files
         * no specifier expansion takes place. 'origin' identifies where the data came from, for logging
         * purposes. */

        static const sd_json_dispatch_field dispatch_table[] = {
                { "id",             SD_JSON_VARIANT_OBJECT,  NULL,                      0,                                       0 }, /* The target identifier, validated by the caller */
                { "description",    SD_JSON_VARIANT_STRING,  sd_json_dispatch_string,   offsetof(Component, description),        0 },
                { "documentation",  SD_JSON_VARIANT_ARRAY,   json_dispatch_http_urls,   offsetof(Component, documentation),      0 },
                { "enabled",        SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_tristate, offsetof(Component, enabled),            0 },
                { "suggest",        SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_tristate, offsetof(Component, suggest),            0 },
                { "minVersion",     SD_JSON_VARIANT_STRING,  json_dispatch_version,     offsetof(Component, min_version),        0 },
                { "maxVersion",     SD_JSON_VARIANT_STRING,  json_dispatch_version,     offsetof(Component, max_version),        0 },
                { "protectVersion", SD_JSON_VARIANT_ARRAY,   json_dispatch_versions,    offsetof(Component, protected_versions), 0 },
                {},
        };

        _cleanup_(component_done) Component d = COMPONENT_NULL;

        /* Dispatch into a temporary object, so that we don't leave a half-initialized one around on failure */
        if (v) {
                r = sd_json_dispatch(v, dispatch_table, SD_JSON_LOG, &d);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse component definition from %s: %m", origin);
        }

        component_done(c);
        *c = TAKE_STRUCT(d);
        return 0;
}
