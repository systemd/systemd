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
                { "Component", "Enabled",                    config_parse_bool,                0,                             &c->enabled       },
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
                        SD_JSON_BUILD_PAIR_BOOLEAN("enabled", c->enabled),
                        SD_JSON_BUILD_PAIR_BOOLEAN("suggest", r > 0),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("minVersion", c->min_version),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("maxVersion", c->max_version),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("protectVersion", c->protected_versions));
        if (r < 0)
                return log_oom();

        return 0;
}
