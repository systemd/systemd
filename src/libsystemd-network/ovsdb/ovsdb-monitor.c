/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-id128.h"

#include "alloc-util.h"
#include "hashmap.h"
#include "id128-util.h"
#include "json-util.h"
#include "log.h"
#include "ovsdb-monitor.h"
#include "set.h"
#include "string-util.h"

/* Per-table cache: maps row UUID -> sd_json_variant* (row object). OVSDB row
 * UUIDs are real RFC 4122 UUIDs, so we parse and key them as sd_id128_t. */
typedef struct OVSDBTableCache {
        Hashmap *rows;    /* sd_id128_t* uuid -> sd_json_variant* (owns both) */
        Hashmap *by_name; /* char* name -> sd_id128_t* (name owned; value aliases a `rows` key) */
} OVSDBTableCache;

struct OVSDBMonitor {
        Hashmap *tables; /* char* table_name -> OVSDBTableCache* */
};

static OVSDBTableCache* ovsdb_table_cache_free(OVSDBTableCache *tc) {
        if (!tc)
                return NULL;

        /* by_name values alias keys owned by `rows`, so free by_name first and only its keys. */
        hashmap_free(tc->by_name);
        hashmap_free(tc->rows);
        return mfree(tc);
}

static const char* ovsdb_row_name(sd_json_variant *row) {
        sd_json_variant *n;

        assert(row);

        n = sd_json_variant_by_key(row, "name");
        return n && sd_json_variant_is_string(n) ? sd_json_variant_string(n) : NULL;
}

/* Rebuild the name->uuid secondary index for a table after its `rows` map changes. Rows are
 * keyed primarily by UUID; this index turns the by-name lookups the reconciler does (one or more
 * per configured netdev, plus Phase 0) from O(rows) linear scans into O(1). Rebuilding it after
 * each apply — rather than maintaining it incrementally — keeps the two maps trivially consistent
 * across inserts, renames and transient duplicate names, at O(rows) per apply, still well below
 * the O(netdevs*rows) of the scans it replaces. The value aliases the live sd_id128_t* key in
 * `rows`, so the index must be rebuilt (here) before any lookup whenever `rows` changes. */
static int ovsdb_table_cache_reindex(OVSDBTableCache *tc) {
        sd_json_variant *row;
        sd_id128_t *uuid_key;
        int r;

        assert(tc);

        hashmap_clear(tc->by_name);

        HASHMAP_FOREACH_KEY(row, uuid_key, tc->rows) {
                const char *name = ovsdb_row_name(row);
                if (!name)
                        continue;

                _cleanup_free_ char *key = strdup(name);
                if (!key)
                        return -ENOMEM;

                /* First-seen row wins on a transient duplicate name (mid-rename, or a stale row
                 * pending GC), matching the previous first-match-stops scan semantics. */
                r = hashmap_ensure_put(&tc->by_name, &string_hash_ops_free, key, uuid_key);
                if (r == -EEXIST)
                        continue;
                if (r < 0)
                        return r;
                TAKE_PTR(key);
        }

        return 0;
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
                sd_id128_t, id128_hash_func, id128_compare_func, free,
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

/* Insert-or-replace tc->rows[*uuid] with new_val, taking ownership of new_val (a ref the caller
 * hands over). The key is duplicated internally. On OOM nothing leaks and the existing entry is
 * never lost: the old key/value stay hashmap-owned and new_val is unref'd. Shared by the
 * apply_initial and apply_update2 (initial/insert/modify) paths. */
static int ovsdb_table_cache_replace_row(OVSDBTableCache *tc, const sd_id128_t *uuid, sd_json_variant *new_val) {
        int r;

        assert(tc);
        assert(uuid);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *val = new_val;
        _cleanup_free_ sd_id128_t *uuid_copy = newdup(sd_id128_t, uuid, 1);
        if (!uuid_copy)
                return -ENOMEM;

        sd_id128_t *old_key = NULL;
        sd_json_variant *old_val = hashmap_get2(tc->rows, uuid, (void**) &old_key);

        r = hashmap_ensure_replace(&tc->rows, &row_hash_ops, uuid_copy, val);
        if (r < 0)
                /* On failure the old key/value stay hashmap-owned; val is unref'd by _cleanup_. */
                return r;

        /* old_val is either a different object (free it) or the same pointer the caller ref'd
         * before calling (balance that ref); either way unref exactly once. */
        sd_json_variant_unref(old_val);
        free(old_key);
        TAKE_PTR(uuid_copy);
        TAKE_PTR(val);
        return 0;
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

                        sd_id128_t parsed;
                        r = sd_id128_from_string(uuid, &parsed);
                        if (r < 0) {
                                log_debug_errno(r, "OVSDB monitor: initial row uuid '%s' in table %s is not a valid UUID, skipping: %m",
                                                uuid, table_name);
                                continue;
                        }

                        r = ovsdb_table_cache_replace_row(tc, &parsed, sd_json_variant_ref(row));
                        if (r < 0)
                                return r;
                }

                r = ovsdb_table_cache_reindex(tc);
                if (r < 0)
                        return r;
        }

        return 0;
}

/* Per RFC 7047 §4.1.7 / OVSDB monitor_cond update2 notation, set/map columns in a
 * "modify" payload carry a *diff* relative to the previous row state, not the new
 * full value:
 *   - set columns: the diff is the symmetric difference; new = old XOR diff
 *   - map columns: each diff pair adds a key, replaces its value, or — when the pair
 *     equals the cached entry — deletes the key (OVSDB ovsdb_datum_apply_diff semantics)
 *
 * We handle the uuid-set columns we consume (Bridge.ports, Port.interfaces,
 * Open_vSwitch.bridges) and the string-map columns we consume (external_ids,
 * Interface.options). The reconciler reads networkd-managed/networkd-config out of
 * external_ids to decide row ownership, so replacing instead of diffing there would drop
 * those keys and orphan managed rows until the next initial snapshot. Remaining scalar
 * columns fall back to plain replacement, which is correct for them.
 *
 * OVSDB encodes a set as ["set", [<atom>, <atom>, ...]] when it has 0 or >1 elements
 * and as just <atom> when it has exactly 1. A uuid atom is ["uuid", "<uuid-str>"].
 * Empty set is ["set", []]. A map is ["map", [["k","v"], ...]]; empty map is ["map", []]. */

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

static bool variant_is_map_wrapper(sd_json_variant *v) {
        if (!v || !sd_json_variant_is_array(v) || sd_json_variant_elements(v) != 2)
                return false;
        sd_json_variant *tag = sd_json_variant_by_index(v, 0);
        sd_json_variant *body = sd_json_variant_by_index(v, 1);
        return tag && body &&
               sd_json_variant_is_string(tag) &&
               sd_json_variant_is_array(body) &&
               streq(sd_json_variant_string(tag), "map");
}

const char* ovsdb_map_get(sd_json_variant *map_col, const char *key) {
        sd_json_variant *pairs;

        assert(key);

        /* map_col is an OVSDB ["map", [[k,v], ...]] column value (e.g. external_ids). Return the
         * string value for `key`, or NULL. No allocation — single-key reads happen on the reconcile
         * hot path (Phase 0 ownership checks), so don't build a whole map for one lookup. */
        if (!variant_is_map_wrapper(map_col))
                return NULL;

        pairs = sd_json_variant_by_index(map_col, 1);
        for (size_t i = 0; i < sd_json_variant_elements(pairs); i++) {
                sd_json_variant *pair = sd_json_variant_by_index(pairs, i), *k, *v;

                if (!pair || !sd_json_variant_is_array(pair) || sd_json_variant_elements(pair) != 2)
                        continue;

                k = sd_json_variant_by_index(pair, 0);
                v = sd_json_variant_by_index(pair, 1);
                if (k && v && sd_json_variant_is_string(k) && sd_json_variant_is_string(v) &&
                    streq(sd_json_variant_string(k), key))
                        return sd_json_variant_string(v);
        }

        return NULL;
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
                if (r < 0 && r != -EEXIST)
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
                                        JSON_BUILD_CONST_STRING("uuid"),
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
                                JSON_BUILD_CONST_STRING("set"),
                                SD_JSON_BUILD_VARIANT(body)));
}

/* Parse an OVSDB string->string map (["map", [["k","v"], ...]]) into a Hashmap.
 * NULL → empty. A non-map encoding or a non-string key/value yields -EINVAL so the
 * caller can skip the modify rather than corrupting the cache. The returned hashmap may
 * be NULL for an empty or absent map; all callers below are NULL-safe. */
static int extract_string_map(sd_json_variant *v, Hashmap **ret) {
        _cleanup_hashmap_free_ Hashmap *out = NULL;
        sd_json_variant *body, *pair;
        int r;

        assert(ret);

        if (v) {
                if (!variant_is_map_wrapper(v))
                        return -EINVAL;

                body = sd_json_variant_by_index(v, 1);
                JSON_VARIANT_ARRAY_FOREACH(pair, body) {
                        if (!sd_json_variant_is_array(pair) || sd_json_variant_elements(pair) != 2)
                                return -EINVAL;

                        sd_json_variant *kv = sd_json_variant_by_index(pair, 0);
                        sd_json_variant *vv = sd_json_variant_by_index(pair, 1);
                        if (!kv || !vv || !sd_json_variant_is_string(kv) || !sd_json_variant_is_string(vv))
                                return -EINVAL;

                        r = hashmap_put_strdup(&out, sd_json_variant_string(kv), sd_json_variant_string(vv));
                        if (r < 0)
                                return r;
                }
        }

        *ret = TAKE_PTR(out);
        return 0;
}

/* Re-encode a string->string Hashmap as an OVSDB ["map", [["k","v"], ...]] variant. */
static int encode_string_map(Hashmap *map, sd_json_variant **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *body = NULL;
        const char *k, *v;
        int r;

        HASHMAP_FOREACH_KEY(v, k, map) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *pair = NULL;
                r = sd_json_build(&pair,
                                SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_STRING(k),
                                        SD_JSON_BUILD_STRING(v)));
                if (r < 0)
                        return r;
                r = sd_json_variant_append_array(&body, pair);
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
                                JSON_BUILD_CONST_STRING("map"),
                                SD_JSON_BUILD_VARIANT(body)));
}

/* True if (table, column) holds a set of uuids in our subscription. This list must stay in
 * sync with the uuid-set columns requested in ovsdb_client_monitor_cond() (ovsdb-client.c):
 * a uuid-set column missing here would have its update2 set-XOR diff stored verbatim as a
 * value (corrupting it). If they ever drift, apply_modify_diff() below fails to recognise the
 * cached encoding and safely skips the modify (resyncing on the next initial snapshot) rather
 * than corrupting the cache, so a stale list degrades gracefully instead of silently. */
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
                } else if (variant_is_map_wrapper(new_val)) {
                        /* Map columns (external_ids, Interface.options): the modify payload is
                         * a diff, not the full map. Apply it with ovsdb_datum_apply_diff()
                         * semantics — a diff pair equal to the cached entry deletes that key,
                         * any other pair inserts the key or replaces its value. We rebuild into
                         * a fresh map rather than mutating in place: hashmap_remove()/_replace()
                         * do not run the hash_ops free functions, so in-place edits would leak. */
                        sd_json_variant *old_val = sd_json_variant_by_key(existing, column);
                        _cleanup_hashmap_free_ Hashmap *old_map = NULL, *diff_map = NULL, *result = NULL;
                        const char *k, *v;

                        r = extract_string_map(old_val, &old_map);
                        if (r < 0) {
                                log_debug_errno(r, "OVSDB monitor: %s.%s cached map unparseable, skipping modify (will resync on next initial): %m",
                                                table, column);
                                continue;
                        }
                        r = extract_string_map(new_val, &diff_map);
                        if (r < 0) {
                                log_debug_errno(r, "OVSDB monitor: %s.%s modify map payload unparseable, skipping: %m",
                                                table, column);
                                continue;
                        }

                        /* Carry over cached keys, applying delete/replace from the diff. */
                        HASHMAP_FOREACH_KEY(v, k, old_map) {
                                const char *dv = hashmap_get(diff_map, k);
                                if (dv) {
                                        if (streq(dv, v))
                                                continue; /* diff repeats the cached pair → delete */
                                        r = hashmap_put_strdup(&result, k, dv); /* value changed */
                                } else
                                        r = hashmap_put_strdup(&result, k, v);  /* untouched */
                                if (r < 0)
                                        return r;
                        }
                        /* Add keys present only in the diff. */
                        HASHMAP_FOREACH_KEY(v, k, diff_map) {
                                if (hashmap_contains(old_map, k))
                                        continue;
                                r = hashmap_put_strdup(&result, k, v);
                                if (r < 0)
                                        return r;
                        }

                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *encoded = NULL;
                        r = encode_string_map(result, &encoded);
                        if (r < 0)
                                return r;
                        r = sd_json_variant_set_field(merged, column, encoded);
                        if (r < 0)
                                return r;
                } else {
                        /* Scalar columns: the modify payload is the new value; replace. */
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

                        sd_id128_t parsed;
                        r = sd_id128_from_string(uuid, &parsed);
                        if (r < 0) {
                                log_debug_errno(r, "OVSDB monitor: update2 row uuid '%s' in table %s is not a valid UUID, skipping: %m",
                                                uuid, table_name);
                                continue;
                        }

                        if (initial_val || insert_val) {
                                /* RFC 7047: "initial" carries the full row value, same as "insert" */
                                sd_json_variant *val = initial_val ?: insert_val;

                                r = ovsdb_table_cache_replace_row(tc, &parsed, sd_json_variant_ref(val));
                                if (r < 0)
                                        return r;

                        } else if (modify_val) {
                                sd_json_variant *existing = hashmap_get(tc->rows, &parsed);
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

                                r = ovsdb_table_cache_replace_row(tc, &parsed, TAKE_PTR(merged));
                                if (r < 0)
                                        return r;

                        } else if (delete_val) {
                                sd_id128_t *old_key = NULL;
                                sd_json_variant *old_val = hashmap_remove2(tc->rows, &parsed, (void**) &old_key);
                                sd_json_variant_unref(old_val);
                                free(old_key);

                                log_debug("OVSDB monitor: deleted row %s from table %s.", uuid, table_name);
                        } else {
                                log_debug("OVSDB monitor: update2 for row %s in table %s has no recognized action, skipping.",
                                          uuid, table_name);
                        }
                }

                r = ovsdb_table_cache_reindex(tc);
                if (r < 0)
                        return r;
        }

        return 0;
}

sd_json_variant* ovsdb_monitor_get(const OVSDBMonitor *m, const char *table, sd_id128_t uuid) {
        if (!m || !table)
                return NULL;

        OVSDBTableCache *tc = hashmap_get((Hashmap *) m->tables, table);
        if (!tc)
                return NULL;

        return hashmap_get(tc->rows, &uuid);
}

int ovsdb_monitor_get_by_name(
                const OVSDBMonitor *m,
                const char *table,
                const char *name,
                sd_id128_t *ret_uuid,
                sd_json_variant **ret_row) {

        if (!m || !table || !name)
                return 0;

        OVSDBTableCache *tc = hashmap_get((Hashmap *) m->tables, table);
        if (!tc)
                return 0;

        sd_id128_t *uuid = hashmap_get(tc->by_name, name);
        if (!uuid)
                return 0;

        if (ret_uuid)
                *ret_uuid = *uuid;
        if (ret_row)
                *ret_row = hashmap_get(tc->rows, uuid);
        return 1;
}

void ovsdb_monitor_foreach(
                const OVSDBMonitor *m,
                const char *table,
                void (*cb)(sd_id128_t uuid, sd_json_variant *row, void *userdata),
                void *userdata) {

        if (!m || !table || !cb)
                return;

        OVSDBTableCache *tc = hashmap_get((Hashmap *) m->tables, table);
        if (!tc)
                return;

        const sd_id128_t *uuid;
        sd_json_variant *row;
        HASHMAP_FOREACH_KEY(row, uuid, tc->rows)
                cb(*uuid, row, userdata);
}

size_t ovsdb_monitor_count(const OVSDBMonitor *m, const char *table) {
        if (!m || !table)
                return 0;

        OVSDBTableCache *tc = hashmap_get((Hashmap *) m->tables, table);
        if (!tc)
                return 0;

        return hashmap_size(tc->rows);
}
