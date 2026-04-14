/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-forward.h"
#include "sd-id128.h"

#include "ovsdb-forward.h"

OVSDBMonitor* ovsdb_monitor_new(void);
OVSDBMonitor* ovsdb_monitor_free(OVSDBMonitor *m);
DEFINE_TRIVIAL_CLEANUP_FUNC(OVSDBMonitor*, ovsdb_monitor_free);

/* Apply a monitor_cond initial reply (update2 format per RFC 7047 §4.1.14).
 * Format: {"Table": {"uuid1": {"initial": {...}}, ...}, ...} */
int ovsdb_monitor_apply_initial(OVSDBMonitor *m, sd_json_variant *reply);

/* Apply an update2 notification.
 * Format: {"Table": {"uuid1": {"insert|modify|delete": ...}}, ...} */
int ovsdb_monitor_apply_update2(OVSDBMonitor *m, sd_json_variant *updates);

/* Return the value for `key` in an OVSDB ["map", [[k,v],...]] column value (e.g. external_ids),
 * or NULL if the column is not a map or the key is absent. Does not allocate. */
const char* ovsdb_map_get(sd_json_variant *map_col, const char *key);

/* Look up a row by table and uuid. Returns NULL if absent. */
sd_json_variant* ovsdb_monitor_get(OVSDBMonitor *m, const char *table, sd_id128_t uuid);

/* Look up a row by its "name" column via the O(1) secondary index. Returns 1 and fills
 * ret_uuid/ret_row (either may be NULL) on a hit, 0 if no such row exists. */
int ovsdb_monitor_get_by_name(
                OVSDBMonitor *m,
                const char *table,
                const char *name,
                sd_id128_t *ret_uuid,
                sd_json_variant **ret_row);

typedef void (*ovsdb_row_callback_t)(sd_id128_t uuid, sd_json_variant *row, void *userdata);

/* Iterate all rows in a table */
void ovsdb_monitor_foreach(
                OVSDBMonitor *m,
                const char *table,
                ovsdb_row_callback_t callback,
                void *userdata);

size_t ovsdb_monitor_count(OVSDBMonitor *m, const char *table);
