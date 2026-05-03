/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-json.h"

/* Validate that an OVSDB get_schema reply contains all required tables.
 * Returns 0 on success, -EPROTONOSUPPORT if missing table, -EBADMSG if
 * structurally invalid, -EINVAL on NULL input. */
int ovsdb_schema_validate(sd_json_variant *schema);

/* Extract the version string from a validated schema. Returns NULL on error. */
const char* ovsdb_schema_version(sd_json_variant *schema);
