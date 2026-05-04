/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "log.h"
#include "macro.h"
#include "ovsdb-schema.h"

static const char* const ovsdb_required_tables[] = {
        "Open_vSwitch",
        "Bridge",
        "Port",
        "Interface",
};

int ovsdb_schema_validate(sd_json_variant *schema) {
        sd_json_variant *tables;

        if (!schema)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "OVSDB schema is NULL.");

        if (!sd_json_variant_is_object(schema))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "OVSDB schema is not a JSON object.");

        tables = sd_json_variant_by_key(schema, "tables");
        if (!tables || !sd_json_variant_is_object(tables))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "OVSDB schema has no valid 'tables' key.");

        for (size_t i = 0; i < ELEMENTSOF(ovsdb_required_tables); i++) {
                sd_json_variant *table;

                table = sd_json_variant_by_key(tables, ovsdb_required_tables[i]);
                if (!table || !sd_json_variant_is_object(table))
                        return log_debug_errno(SYNTHETIC_ERRNO(EPROTONOSUPPORT),
                                               "OVSDB schema missing required table '%s'.",
                                               ovsdb_required_tables[i]);
        }

        return 0;
}

const char* ovsdb_schema_version(sd_json_variant *schema) {
        sd_json_variant *v;

        if (!schema)
                return NULL;

        v = sd_json_variant_by_key(schema, "version");
        if (!v)
                return NULL;

        if (!sd_json_variant_is_string(v))
                return NULL;

        return sd_json_variant_string(v);
}
