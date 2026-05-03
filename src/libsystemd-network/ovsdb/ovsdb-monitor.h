/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-json.h"

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

/* Look up a row by table and uuid. Returns NULL if absent. */
sd_json_variant* ovsdb_monitor_get(const OVSDBMonitor *m, const char *table, const char *uuid);

/* Iterate all rows in a table */
void ovsdb_monitor_foreach(
                const OVSDBMonitor *m,
                const char *table,
                void (*cb)(const char *uuid, sd_json_variant *row, void *userdata),
                void *userdata);

size_t ovsdb_monitor_count(const OVSDBMonitor *m, const char *table);
