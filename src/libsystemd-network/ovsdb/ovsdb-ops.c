/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "ovsdb-ops.h"

int ovsdb_op_insert(const char *table, const char *uuid_name, sd_json_variant *row, sd_json_variant **ret_op) {
        assert(table);
        assert(row);
        assert(ret_op);

        return sd_json_buildo(
                        ret_op,
                        SD_JSON_BUILD_PAIR_STRING("op", "insert"),
                        SD_JSON_BUILD_PAIR_STRING("table", table),
                        SD_JSON_BUILD_PAIR_VARIANT("row", row),
                        SD_JSON_BUILD_PAIR_CONDITION(!!uuid_name, "uuid-name", SD_JSON_BUILD_STRING(uuid_name)));
}

int ovsdb_op_update(const char *table, sd_json_variant *where, sd_json_variant *row, sd_json_variant **ret_op) {
        assert(table);
        assert(where);
        assert(row);
        assert(ret_op);

        return sd_json_buildo(
                        ret_op,
                        SD_JSON_BUILD_PAIR_STRING("op", "update"),
                        SD_JSON_BUILD_PAIR_STRING("table", table),
                        SD_JSON_BUILD_PAIR_VARIANT("where", where),
                        SD_JSON_BUILD_PAIR_VARIANT("row", row));
}

int ovsdb_op_mutate(const char *table, sd_json_variant *where, sd_json_variant *mutations, sd_json_variant **ret_op) {
        assert(table);
        assert(where);
        assert(mutations);
        assert(ret_op);

        return sd_json_buildo(
                        ret_op,
                        SD_JSON_BUILD_PAIR_STRING("op", "mutate"),
                        SD_JSON_BUILD_PAIR_STRING("table", table),
                        SD_JSON_BUILD_PAIR_VARIANT("where", where),
                        SD_JSON_BUILD_PAIR_VARIANT("mutations", mutations));
}

int ovsdb_op_delete(const char *table, sd_json_variant *where, sd_json_variant **ret_op) {
        assert(table);
        assert(where);
        assert(ret_op);

        return sd_json_buildo(
                        ret_op,
                        SD_JSON_BUILD_PAIR_STRING("op", "delete"),
                        SD_JSON_BUILD_PAIR_STRING("table", table),
                        SD_JSON_BUILD_PAIR_VARIANT("where", where));
}

int ovsdb_op_select(const char *table, sd_json_variant *where, sd_json_variant *columns, sd_json_variant **ret_op) {
        assert(table);
        assert(where);
        assert(ret_op);

        return sd_json_buildo(
                        ret_op,
                        SD_JSON_BUILD_PAIR_STRING("op", "select"),
                        SD_JSON_BUILD_PAIR_STRING("table", table),
                        SD_JSON_BUILD_PAIR_VARIANT("where", where),
                        SD_JSON_BUILD_PAIR_CONDITION(!!columns, "columns", SD_JSON_BUILD_VARIANT(columns)));
}

int ovsdb_op_comment(const char *text, sd_json_variant **ret_op) {
        assert(text);
        assert(ret_op);

        return sd_json_buildo(
                        ret_op,
                        SD_JSON_BUILD_PAIR_STRING("op", "comment"),
                        SD_JSON_BUILD_PAIR_STRING("comment", text));
}

int ovsdb_op_abort(sd_json_variant **ret_op) {
        assert(ret_op);

        return sd_json_buildo(
                        ret_op,
                        SD_JSON_BUILD_PAIR_STRING("op", "abort"));
}

int ovsdb_where_uuid(const char *uuid, sd_json_variant **ret_where) {
        assert(uuid);
        assert(ret_where);

        /* Produces: [["_uuid", "==", ["uuid", "<uuid>"]]] */
        return sd_json_build(
                        ret_where,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_STRING("_uuid"),
                                        SD_JSON_BUILD_STRING("=="),
                                        SD_JSON_BUILD_ARRAY(
                                                SD_JSON_BUILD_STRING("uuid"),
                                                SD_JSON_BUILD_STRING(uuid)))));
}

int ovsdb_where_all(sd_json_variant **ret_where) {
        assert(ret_where);

        return sd_json_build(ret_where, SD_JSON_BUILD_EMPTY_ARRAY);
}
