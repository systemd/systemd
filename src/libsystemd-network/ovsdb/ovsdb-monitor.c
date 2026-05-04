/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "hashmap.h"
#include "json-util.h"
#include "log.h"
#include "ovsdb-monitor.h"
#include "set.h"
#include "string-util.h"

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

/* Per RFC 7047 §4.1.7 / OVSDB monitor_cond update2 notation, set/map columns in a
 * "modify" payload carry a *diff* relative to the previous row state, not the new
 * full value:
 *   - set columns: the diff is the symmetric difference; new = old XOR diff
 *   - map columns: the diff lists key-value pairs to delete and to insert
 *
 * We currently support uuid-set columns specifically (Bridge.ports, Port.interfaces,
 * Open_vSwitch.bridges) because those are the only ones we actually consume. Other
 * encodings fall back to plain replacement, which is correct for scalars and an
 * acceptable approximation for the maps we read (external_ids — informational).
 *
 * OVSDB encodes a set as ["set", [<atom>, <atom>, ...]] when it has 0 or >1 elements
 * and as just <atom> when it has exactly 1. A uuid atom is ["uuid", "<uuid-str>"].
 * Empty set is ["set", []]. */

static bool variant_is_uuid_atom(sd_json_variant *v) {
        if (!v || !sd_json_variant_is_array(v) || sd_json_variant_elements(v) != 2)
                return false;
        sd_json_variant *tag = sd_json_variant_by_index(v, 0);
        sd_json_variant *body = sd_json_variant_by_index(v, 1);
        return tag && body &&
               sd_json_variant_is_string(tag) &&
               sd_json_variant_is_string(body) &&
               streq(sd_json_variant_string(tag), "uuid");
}

static bool variant_is_set_wrapper(sd_json_variant *v) {
        if (!v || !sd_json_variant_is_array(v) || sd_json_variant_elements(v) != 2)
                return false;
        sd_json_variant *tag = sd_json_variant_by_index(v, 0);
        sd_json_variant *body = sd_json_variant_by_index(v, 1);
        return tag && body &&
               sd_json_variant_is_string(tag) &&
               sd_json_variant_is_array(body) &&
               streq(sd_json_variant_string(tag), "set");
}

/* Extract uuid strings from an OVSDB-encoded uuid set into a string set.
 * Accepts the three legitimate encodings:
 *   - NULL                                  → empty
 *   - ["set", [["uuid", "<u>"], ...]]       → multi/empty
 *   - ["uuid", "<u>"]                       → singleton
 * Anything else is left for the caller to fall back to replacement semantics. */
static int extract_uuid_set(sd_json_variant *v, Set **ret) {
        _cleanup_set_free_ Set *out = NULL;
        int r;

        assert(ret);

        out = set_new(&string_hash_ops_free);
        if (!out)
                return -ENOMEM;

        if (!v) {
                *ret = TAKE_PTR(out);
                return 0;
        }

        if (variant_is_uuid_atom(v)) {
                _cleanup_free_ char *u = strdup(sd_json_variant_string(sd_json_variant_by_index(v, 1)));
                if (!u)
                        return -ENOMEM;
                r = set_consume(out, TAKE_PTR(u));
                if (r < 0)
                        return r;
        } else if (variant_is_set_wrapper(v)) {
                sd_json_variant *body = sd_json_variant_by_index(v, 1);
                sd_json_variant *atom;
                JSON_VARIANT_ARRAY_FOREACH(atom, body) {
                        if (!variant_is_uuid_atom(atom))
                                return -EINVAL;
                        char *u = strdup(sd_json_variant_string(sd_json_variant_by_index(atom, 1)));
                        if (!u)
                                return -ENOMEM;
                        r = set_consume(out, u);
                        if (r < 0 && r != -EEXIST)
                                return r;
                }
        } else
                return -EINVAL;

        *ret = TAKE_PTR(out);
        return 0;
}

/* Re-encode a string set of uuids as an OVSDB ["set", [["uuid", ...], ...]] variant,
 * always using the multi-element wrapper (even for singletons) — that's what existing
 * callers like ovs_monitor_get_bridge_ports expect. */
static int encode_uuid_set(Set *uuids, sd_json_variant **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *body = NULL;
        const char *u;
        int r;

        SET_FOREACH(u, uuids) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *atom = NULL;
                r = sd_json_build(&atom,
                                SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_STRING("uuid"),
                                        SD_JSON_BUILD_STRING(u)));
                if (r < 0)
                        return r;
                r = sd_json_variant_append_array(&body, atom);
                if (r < 0)
                        return r;
        }

        if (!body) {
                r = sd_json_build(&body, SD_JSON_BUILD_EMPTY_ARRAY);
                if (r < 0)
                        return r;
        }

        return sd_json_build(ret,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_STRING("set"),
                                SD_JSON_BUILD_VARIANT(body)));
}

/* True if (table, column) holds a set of uuids in our subscription. */
static bool is_uuid_set_column(const char *table, const char *column) {
        return (streq(table, "Bridge")       && streq(column, "ports")) ||
               (streq(table, "Port")         && streq(column, "interfaces")) ||
               (streq(table, "Open_vSwitch") && streq(column, "bridges"));
}

/* For each column in `modify`, decide whether to apply the OVSDB set-diff
 * (XOR with the existing value) or fall back to plain replacement. Mutates
 * `merged` in place. */
static int apply_modify_diff(const char *table, sd_json_variant *existing,
                             sd_json_variant *modify, sd_json_variant **merged) {
        const char *column;
        sd_json_variant *new_val;
        int r;

        assert(table);
        assert(modify);
        assert(merged);
        assert(*merged);

        JSON_VARIANT_OBJECT_FOREACH(column, new_val, modify) {
                if (is_uuid_set_column(table, column)) {
                        sd_json_variant *old_val = sd_json_variant_by_key(existing, column);
                        _cleanup_set_free_ Set *old_set = NULL, *diff_set = NULL;

                        r = extract_uuid_set(old_val, &old_set);
                        if (r < 0) {
                                /* Cached encoding unrecognised — leave the column untouched
                                 * rather than overwriting it with the modify payload, which is
                                 * a set-XOR diff (RFC 7047 §4.1.7), not a full value. Storing
                                 * the diff as if it were a value would corrupt downstream
                                 * lookups on Bridge.ports / Port.interfaces / Open_vSwitch.bridges. */
                                log_debug("OVSDB monitor: %s.%s cached value unparseable, skipping modify (will resync on next initial)",
                                          table, column);
                                continue;
                        }
                        r = extract_uuid_set(new_val, &diff_set);
                        if (r < 0) {
                                log_debug("OVSDB monitor: %s.%s modify payload unparseable, skipping",
                                          table, column);
                                continue;
                        }

                        /* Symmetric difference: new = old XOR diff. */
                        const char *u;
                        SET_FOREACH(u, diff_set) {
                                if (set_contains(old_set, u))
                                        free(set_remove(old_set, u));
                                else {
                                        char *copy = strdup(u);
                                        if (!copy)
                                                return -ENOMEM;
                                        r = set_consume(old_set, copy);
                                        if (r < 0 && r != -EEXIST)
                                                return r;
                                }
                        }

                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *encoded = NULL;
                        r = encode_uuid_set(old_set, &encoded);
                        if (r < 0)
                                return r;
                        r = sd_json_variant_set_field(merged, column, encoded);
                        if (r < 0)
                                return r;
                } else {
                        /* Scalar columns and unknown columns: replace. Maps are
                         * approximated as replace too — accurate handling would
                         * require schema-aware diff. */
                        r = sd_json_variant_set_field(merged, column, new_val);
                        if (r < 0)
                                return r;
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

                                /* Clone existing row and apply per-column diff
                                 * (set XOR for uuid sets, replacement otherwise). */
                                _cleanup_(sd_json_variant_unrefp) sd_json_variant *merged = NULL;
                                merged = sd_json_variant_ref(existing);

                                r = apply_modify_diff(table_name, existing, modify_val, &merged);
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
