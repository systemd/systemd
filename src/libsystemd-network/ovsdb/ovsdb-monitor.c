/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "hashmap.h"
#include "json-util.h"
#include "log.h"
#include "ovsdb-monitor.h"

/* Per-table cache: maps row UUID (string) -> sd_json_variant* (row object) */
typedef struct OVSDBTableCache {
        Hashmap *rows; /* char* uuid -> sd_json_variant* */
} OVSDBTableCache;

struct OVSDBMonitor {
        Hashmap *tables; /* char* table_name -> OVSDBTableCache* */
};

static OVSDBTableCache* ovsdb_table_cache_free(OVSDBTableCache *tc) {
        if (!tc)
                return NULL;

        hashmap_free(tc->rows);
        return mfree(tc);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(OVSDBTableCache*, ovsdb_table_cache_free);

DEFINE_PRIVATE_HASH_OPS_FULL(
                table_cache_hash_ops,
                char, string_hash_func, string_compare_func, free,
                OVSDBTableCache, ovsdb_table_cache_free);

static void json_variant_unref_void(sd_json_variant *v) {
        sd_json_variant_unref(v);
}

DEFINE_PRIVATE_HASH_OPS_FULL(
                row_hash_ops,
                char, string_hash_func, string_compare_func, free,
                sd_json_variant, json_variant_unref_void);

static int ovsdb_table_cache_ensure(OVSDBMonitor *m, const char *table, OVSDBTableCache **ret) {
        OVSDBTableCache *tc;
        int r;

        assert(m);
        assert(table);

        tc = hashmap_get(m->tables, table);
        if (tc) {
                if (ret)
                        *ret = tc;
                return 0;
        }

        _cleanup_(ovsdb_table_cache_freep) OVSDBTableCache *new_tc = NULL;
        new_tc = new0(OVSDBTableCache, 1);
        if (!new_tc)
                return -ENOMEM;

        _cleanup_free_ char *key = strdup(table);
        if (!key)
                return -ENOMEM;

        r = hashmap_ensure_put(&m->tables, &table_cache_hash_ops, key, new_tc);
        if (r < 0)
                return r;

        TAKE_PTR(key);
        tc = TAKE_PTR(new_tc);

        if (ret)
                *ret = tc;
        return 1;
}

OVSDBMonitor* ovsdb_monitor_new(void) {
        return new0(OVSDBMonitor, 1);
}

OVSDBMonitor* ovsdb_monitor_free(OVSDBMonitor *m) {
        if (!m)
                return NULL;

        hashmap_free(m->tables);
        return mfree(m);
}

int ovsdb_monitor_apply_initial(OVSDBMonitor *m, sd_json_variant *reply) {
        const char *table_name;
        sd_json_variant *table_data;
        int r;

        if (!m)
                return 0;
        if (!reply)
                return 0;

        JSON_VARIANT_OBJECT_FOREACH(table_name, table_data, reply) {
                OVSDBTableCache *tc;

                r = ovsdb_table_cache_ensure(m, table_name, &tc);
                if (r < 0)
                        return r;

                const char *uuid;
                sd_json_variant *row_wrapper;

                JSON_VARIANT_OBJECT_FOREACH(uuid, row_wrapper, table_data) {
                        sd_json_variant *row = sd_json_variant_by_key(row_wrapper, "initial");
                        if (!row) {
                                log_debug("OVSDB monitor: initial row %s in table %s lacks 'initial' key, skipping.",
                                          uuid, table_name);
                                continue;
                        }

                        _cleanup_free_ char *uuid_copy = strdup(uuid);
                        if (!uuid_copy)
                                return -ENOMEM;

                        sd_json_variant *new_ref = sd_json_variant_ref(row);

                        /* Insert-or-replace atomically so the old entry is never lost on OOM */
                        char *old_key = NULL;
                        sd_json_variant *old_val = hashmap_get2(tc->rows, uuid, (void**) &old_key);

                        r = hashmap_ensure_replace(&tc->rows, &row_hash_ops, uuid_copy, new_ref);
                        if (r < 0) {
                                /* On failure, old_key/old_val remain hashmap-owned — don't free them */
                                sd_json_variant_unref(new_ref);
                                return r;
                        }

                        sd_json_variant_unref(old_val);
                        free(old_key);
                        TAKE_PTR(uuid_copy);
                }
        }

        return 0;
}

int ovsdb_monitor_apply_update2(OVSDBMonitor *m, sd_json_variant *updates) {
        const char *table_name;
        sd_json_variant *table_data;
        int r;

        if (!m)
                return 0;
        if (!updates)
                return 0;

        JSON_VARIANT_OBJECT_FOREACH(table_name, table_data, updates) {
                OVSDBTableCache *tc;

                r = ovsdb_table_cache_ensure(m, table_name, &tc);
                if (r < 0)
                        return r;

                const char *uuid;
                sd_json_variant *delta;

                JSON_VARIANT_OBJECT_FOREACH(uuid, delta, table_data) {
                        sd_json_variant *initial_val = sd_json_variant_by_key(delta, "initial");
                        sd_json_variant *insert_val = sd_json_variant_by_key(delta, "insert");
                        sd_json_variant *modify_val = sd_json_variant_by_key(delta, "modify");
                        sd_json_variant *delete_val = sd_json_variant_by_key(delta, "delete");

                        if (initial_val || insert_val) {
                                /* RFC 7047: "initial" carries the full row value, same as "insert" */
                                sd_json_variant *val = initial_val ?: insert_val;
                                _cleanup_free_ char *uuid_copy = strdup(uuid);
                                if (!uuid_copy)
                                        return -ENOMEM;

                                sd_json_variant *new_ref = sd_json_variant_ref(val);

                                /* Insert-or-replace atomically so the old entry is never lost on OOM */
                                char *old_key = NULL;
                                sd_json_variant *old_val = hashmap_get2(tc->rows, uuid, (void**) &old_key);

                                r = hashmap_ensure_replace(&tc->rows, &row_hash_ops, uuid_copy, new_ref);
                                if (r < 0) {
                                        /* On failure, old_key/old_val remain hashmap-owned */
                                        sd_json_variant_unref(new_ref);
                                        return r;
                                }

                                sd_json_variant_unref(old_val);
                                free(old_key);
                                TAKE_PTR(uuid_copy);

                        } else if (modify_val) {
                                sd_json_variant *existing = hashmap_get(tc->rows, uuid);
                                if (!existing) {
                                        log_debug("OVSDB monitor: modify for unknown row %s in table %s, skipping.",
                                                  uuid, table_name);
                                        continue;
                                }

                                /* Clone existing row and merge modifications */
                                _cleanup_(sd_json_variant_unrefp) sd_json_variant *merged = NULL;
                                merged = sd_json_variant_ref(existing);

                                r = sd_json_variant_merge_object(&merged, modify_val);
                                if (r < 0)
                                        return r;

                                /* Replace in hashmap atomically so the old entry is never lost on OOM */
                                _cleanup_free_ char *uuid_copy = strdup(uuid);
                                if (!uuid_copy)
                                        return -ENOMEM;

                                char *old_key = NULL;
                                sd_json_variant *old_val = hashmap_get2(tc->rows, uuid, (void**) &old_key);

                                sd_json_variant *new_val = TAKE_PTR(merged); /* neutralize _cleanup_ */

                                r = hashmap_ensure_replace(&tc->rows, &row_hash_ops, uuid_copy, new_val);
                                if (r < 0) {
                                        /* On failure, old_key/old_val remain hashmap-owned */
                                        sd_json_variant_unref(new_val);
                                        return r;
                                }

                                if (old_val != new_val)
                                        sd_json_variant_unref(old_val);
                                free(old_key);
                                TAKE_PTR(uuid_copy);

                        } else if (delete_val) {
                                char *old_key = NULL;
                                sd_json_variant *old_val = hashmap_remove2(tc->rows, uuid, (void**) &old_key);
                                sd_json_variant_unref(old_val);
                                free(old_key);

                                log_debug("OVSDB monitor: deleted row %s from table %s.", uuid, table_name);
                        } else {
                                log_debug("OVSDB monitor: update2 for row %s in table %s has no recognized action, skipping.",
                                          uuid, table_name);
                        }
                }
        }

        return 0;
}

sd_json_variant* ovsdb_monitor_get(const OVSDBMonitor *m, const char *table, const char *uuid) {
        if (!m || !table || !uuid)
                return NULL;

        OVSDBTableCache *tc = hashmap_get((Hashmap *) m->tables, table);
        if (!tc)
                return NULL;

        return hashmap_get(tc->rows, uuid);
}

void ovsdb_monitor_foreach(
                const OVSDBMonitor *m,
                const char *table,
                void (*cb)(const char *uuid, sd_json_variant *row, void *userdata),
                void *userdata) {

        if (!m || !table || !cb)
                return;

        OVSDBTableCache *tc = hashmap_get((Hashmap *) m->tables, table);
        if (!tc)
                return;

        const char *uuid;
        sd_json_variant *row;
        HASHMAP_FOREACH_KEY(row, uuid, tc->rows)
                cb(uuid, row, userdata);
}

size_t ovsdb_monitor_count(const OVSDBMonitor *m, const char *table) {
        if (!m || !table)
                return 0;

        OVSDBTableCache *tc = hashmap_get((Hashmap *) m->tables, table);
        if (!tc)
                return 0;

        return hashmap_size(tc->rows);
}
