/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "log.h"
#include "ovsdb-schema.h"
#include "strv.h"

int ovsdb_schema_validate(sd_json_variant *schema) {
        sd_json_variant *tables;

        if (!schema)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "OVSDB schema is NULL.");

        if (!sd_json_variant_is_object(schema))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "OVSDB schema is not a JSON object.");

        tables = sd_json_variant_by_key(schema, "tables");
        if (!tables || !sd_json_variant_is_object(tables))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "OVSDB schema has no valid 'tables' key.");

        FOREACH_STRING(table_name, "Open_vSwitch", "Bridge", "Port", "Interface") {
                sd_json_variant *table = sd_json_variant_by_key(tables, table_name);
                if (!table || !sd_json_variant_is_object(table))
                        return log_debug_errno(SYNTHETIC_ERRNO(EPROTONOSUPPORT),
                                               "OVSDB schema missing required table '%s'.",
                                               table_name);
        }

        return 0;
}

const char* ovsdb_schema_version(sd_json_variant *schema) {
        return sd_json_variant_string(sd_json_variant_by_key(schema, "version"));
}
