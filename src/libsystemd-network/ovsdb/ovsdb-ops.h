/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-json.h"

/* RFC 7047 transact operation builders.
 * All return 0 on success, negative errno on failure, output via ret_* parameter. */

int ovsdb_op_insert(const char *table, const char *uuid_name, sd_json_variant *row, sd_json_variant **ret_op);
int ovsdb_op_update(const char *table, sd_json_variant *where, sd_json_variant *row, sd_json_variant **ret_op);
int ovsdb_op_mutate(const char *table, sd_json_variant *where, sd_json_variant *mutations, sd_json_variant **ret_op);
int ovsdb_op_delete(const char *table, sd_json_variant *where, sd_json_variant **ret_op);
int ovsdb_op_select(const char *table, sd_json_variant *where, sd_json_variant *columns, sd_json_variant **ret_op);
int ovsdb_op_comment(const char *text, sd_json_variant **ret_op);
int ovsdb_op_abort(sd_json_variant **ret_op);

int ovsdb_where_uuid(const char *uuid, sd_json_variant **ret_where);
int ovsdb_where_all(sd_json_variant **ret_where);
