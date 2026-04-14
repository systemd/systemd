/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-event.h"
#include "sd-id128.h"
#include "sd-json.h"

#include "extract-word.h"
#include "fs-util.h"
#include "hashmap.h"
#include "in-addr-util.h"
#include "json-util.h"
#include "netdev.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "networkd-ovs.h"
#include "ovs-bridge.h"
#include "ovs-port.h"
#include "ovs-tunnel.h"
#include "ovsdb/ovsdb-client.h"
#include "ovsdb/ovsdb-monitor.h"
#include "ovsdb/ovsdb-ops.h"
#include "random-util.h"
#include "set.h"
#include "siphash24.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "vlan-util.h"

/* Extract a value from an OVSDB map-encoded column.
 * Map encoding: ["map", [["k1","v1"], ["k2","v2"], ...]] */
static const char* ovs_get_external_id(sd_json_variant *row, const char *key) {
        assert(row);
        assert(key);

        /* external_ids is an OVSDB map column; decode it via the shared ovsdb_map_get() rather
         * than re-implementing the ["map",[...]] walk here. */
        return ovsdb_map_get(sd_json_variant_by_key(row, "external_ids"), key);
}

/* Build the OVSDB ["uuid", "<uuid>"] reference atom for a real (already-committed) row UUID.
 * (For rows being created in the same transact use ovs_build_named_uuid_ref() instead.) */
static int ovs_build_uuid_ref(sd_id128_t uuid, sd_json_variant **ret) {
        return sd_json_build(ret,
                        SD_JSON_BUILD_ARRAY(
                                JSON_BUILD_CONST_STRING("uuid"),
                                SD_JSON_BUILD_STRING(SD_ID128_TO_UUID_STRING(uuid))));
}

struct ovs_delete_ctx {
        Manager *m;
        sd_json_variant **ops;
        int error;
};

static void ovs_check_bridge_delete(sd_id128_t uuid, sd_json_variant *row, void *userdata) {
        struct ovs_delete_ctx *ctx = ASSERT_PTR(userdata);
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *where = NULL, *delete_op = NULL,
                *ovs_where = NULL, *mutations = NULL, *mutate_op = NULL, *bridge_ref = NULL;
        sd_json_variant *name_v;
        const char *managed, *name;
        NetDev *netdev;
        Network *network;
        int r;

        assert(row);

        if (ctx->error < 0)
                return;

        managed = ovs_get_external_id(row, "networkd-managed");
        if (!managed || !streq(managed, "true"))
                return;

        name_v = sd_json_variant_by_key(row, "name");
        if (!name_v || !sd_json_variant_is_string(name_v))
                return;
        name = sd_json_variant_string(name_v);

        /* Still configured as OVS bridge? Keep it. */
        if (netdev_get(ctx->m, name, &netdev) >= 0 && netdev->kind == NETDEV_KIND_OVS_BRIDGE)
                return;

        /* Check if any .network still references this bridge via OVSBridge= */
        ORDERED_HASHMAP_FOREACH(network, ctx->m->networks)
                if (network->ovs_bridge_name && streq(network->ovs_bridge_name, name))
                        return;

        log_debug("OVS bridge '%s' (uuid=%s) no longer in config, queuing delete",
                  name, SD_ID128_TO_UUID_STRING(uuid));

        /* Mutate Open_vSwitch: bridges -= ["set", [["uuid", "<uuid>"]]]
         * Must come before the DELETE — drop the strong reference first. */
        r = ovsdb_where_all(&ovs_where);
        if (r < 0)
                goto fail;

        r = ovs_build_uuid_ref(uuid, &bridge_ref);
        if (r < 0)
                goto fail;

        r = sd_json_build(
                        &mutations,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_ARRAY(
                                        JSON_BUILD_CONST_STRING("bridges"),
                                        JSON_BUILD_CONST_STRING("delete"),
                                        SD_JSON_BUILD_ARRAY(
                                                JSON_BUILD_CONST_STRING("set"),
                                                SD_JSON_BUILD_ARRAY(
                                                        SD_JSON_BUILD_VARIANT(bridge_ref))))));
        if (r < 0)
                goto fail;

        r = ovsdb_op_mutate("Open_vSwitch", ovs_where, mutations, &mutate_op);
        if (r < 0)
                goto fail;

        r = sd_json_variant_append_array(ctx->ops, mutate_op);
        if (r < 0)
                goto fail;

        /* Delete the Bridge row */
        r = ovsdb_where_uuid(uuid, &where);
        if (r < 0)
                goto fail;

        r = ovsdb_op_delete("Bridge", where, &delete_op);
        if (r < 0)
                goto fail;

        r = sd_json_variant_append_array(ctx->ops, delete_op);
        if (r < 0)
                goto fail;

        return;

fail:
        ctx->error = r;
}

static bool ovs_port_still_configured(Manager *m, const char *name) {
        NetDev *netdev;
        Link *link;

        assert(m);
        assert(name);

        /* Match a bridge's own local port (bridge creates a Port with its name) or a
         * standalone OVS_PORT/OVS_TUNNEL netdev — both share the same name lookup. */
        if (netdev_get(m, name, &netdev) >= 0 &&
            IN_SET(netdev->kind, NETDEV_KIND_OVS_BRIDGE, NETDEV_KIND_OVS_PORT, NETDEV_KIND_OVS_TUNNEL))
                return true;

        /* Check if any Link is attached as a standalone Port via .network OVSBridge=.
         * Iterate Links (not network->match.ifname) so glob/MAC/Driver matchers
         * are honored — same approach as ovs_reconcile_network_port.
         *
         * Note: OVSBond= members are deliberately NOT counted here. Bond members
         * are represented as Interface rows inside the bond's Port, not as a
         * standalone same-name Port row. Treating them as live would block
         * orphan cleanup when an interface migrates from OVSBridge= (standalone
         * Port) to OVSBond= (Interface inside bond Port) — the old standalone
         * Port would never be deleted. */
        HASHMAP_FOREACH(link, m->links_by_index) {
                if (!link->network)
                        continue;
                if (!link->network->ovs_bridge_name)
                        continue;
                if (!link->ifname)
                        continue;
                if (streq(link->ifname, name))
                        return true;
        }

        return false;
}

/* The Phase-0 deletion predicate, shared by ovs_check_port_delete() (which emits the deletes)
 * and the bond reconciler (which must avoid reusing a doomed Interface's UUID): true if `row`
 * is a networkd-managed Port that is no longer configured and will therefore be DELETEd this
 * reconcile, cascading to its same-named Interface row. On true, *ret_name (if non-NULL)
 * aliases the row's name, valid for the monitor cache's lifetime. Keeping this in one place
 * stops the two callers' criteria from silently drifting apart. */
static bool ovs_managed_port_pending_delete(Manager *m, sd_json_variant *row, const char **ret_name) {
        sd_json_variant *name_v;
        const char *managed, *name;

        assert(m);
        assert(row);

        managed = ovs_get_external_id(row, "networkd-managed");
        if (!managed || !streq(managed, "true"))
                return false;  /* not ours → Phase 0 leaves it alone */

        name_v = sd_json_variant_by_key(row, "name");
        if (!name_v || !sd_json_variant_is_string(name_v))
                return false;
        name = sd_json_variant_string(name_v);

        if (ovs_port_still_configured(m, name))
                return false;  /* still configured → not deleted */

        if (ret_name)
                *ret_name = name;
        return true;
}

/* Collect the names of all standalone Ports being deleted this reconcile, so the bond
 * reconciler can decide reuse-vs-INSERT per member with an O(1) lookup instead of re-scanning
 * the whole Port cache (and all links) once per member. */
struct ovs_doomed_ports_ctx {
        Manager *m;
        Set *names;
        int error;
};

static void ovs_collect_doomed_ports_cb(sd_id128_t uuid, sd_json_variant *row, void *userdata) {
        struct ovs_doomed_ports_ctx *ctx = ASSERT_PTR(userdata);
        const char *name;
        int r;

        assert(row);

        if (ctx->error < 0)
                return;
        if (!ovs_managed_port_pending_delete(ctx->m, row, &name))
                return;

        r = set_put_strdup(&ctx->names, name);
        if (r < 0)
                ctx->error = r;
}

/* Emit a Bridge.ports mutate op that inserts or deletes a single port UUID reference.
 *
 * With bridge_name set it targets that one bridge by name. With bridge_name NULL it targets
 * all bridges (ovsdb_where_all) — a no-op on the non-parent rows since port UUIDs are globally
 * unique — which reliably unlinks a port regardless of which bridge currently owns it (e.g.
 * after Bridge= changed in the same edit, where a name-matched mutate would miss it). Because
 * Bridge.ports is a strong reference, a "delete" here must precede the Port DELETE. */
static int ovs_emit_bridge_ports_mutate(
                const char *bridge_name,  /* NULL = all bridges */
                sd_id128_t port_uuid,
                const char *op_verb,      /* "insert" or "delete" */
                sd_json_variant **ops) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *where = NULL, *port_uuid_ref = NULL,
                *mutations = NULL, *mutate_op = NULL;
        int r;

        assert(op_verb);
        assert(ops);

        if (bridge_name)
                r = sd_json_build(&where,
                                SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_ARRAY(
                                                JSON_BUILD_CONST_STRING("name"),
                                                JSON_BUILD_CONST_STRING("=="),
                                                SD_JSON_BUILD_STRING(bridge_name))));
        else
                r = ovsdb_where_all(&where);
        if (r < 0)
                return r;

        r = ovs_build_uuid_ref(port_uuid, &port_uuid_ref);
        if (r < 0)
                return r;

        r = sd_json_build(&mutations,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_ARRAY(
                                        JSON_BUILD_CONST_STRING("ports"),
                                        SD_JSON_BUILD_STRING(op_verb),
                                        SD_JSON_BUILD_ARRAY(
                                                JSON_BUILD_CONST_STRING("set"),
                                                SD_JSON_BUILD_ARRAY(
                                                        SD_JSON_BUILD_VARIANT(port_uuid_ref))))));
        if (r < 0)
                return r;

        r = ovsdb_op_mutate("Bridge", where, mutations, &mutate_op);
        if (r < 0)
                return r;

        return sd_json_variant_append_array(ops, mutate_op);
}

static void ovs_check_port_delete(sd_id128_t uuid, sd_json_variant *row, void *userdata) {
        struct ovs_delete_ctx *ctx = ASSERT_PTR(userdata);
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *where = NULL, *delete_op = NULL;
        const char *name;
        int r;

        assert(row);

        if (ctx->error < 0)
                return;

        if (!ovs_managed_port_pending_delete(ctx->m, row, &name))
                return;

        log_debug("OVS port '%s' (uuid=%s) no longer in config, queuing delete",
                  name, SD_ID128_TO_UUID_STRING(uuid));

        /* Unlink the port from its owning bridge (strong ref) before deleting it. */
        r = ovs_emit_bridge_ports_mutate(/* bridge_name= */ NULL, uuid, "delete", ctx->ops);
        if (r < 0)
                goto fail;

        /* Delete the Port row — OVSDB cascades Interface deletion. */
        r = ovsdb_where_uuid(uuid, &where);
        if (r < 0)
                goto fail;

        r = ovsdb_op_delete("Port", where, &delete_op);
        if (r < 0)
                goto fail;

        r = sd_json_variant_append_array(ctx->ops, delete_op);
        if (r < 0)
                goto fail;

        return;

fail:
        ctx->error = r;
}

static int ovs_reconcile_delete(Manager *m, sd_json_variant **ops) {
        OVSDBMonitor *mon;
        struct ovs_delete_ctx ctx;

        assert(m);
        assert(ops);

        mon = ovsdb_client_get_monitor(m->ovsdb);
        if (!mon)
                return 0;

        ctx = (struct ovs_delete_ctx) {
                .m = m,
                .ops = ops,
                .error = 0,
        };

        /* Delete orphaned bridges first (removes contained ports too) */
        ovsdb_monitor_foreach(mon, "Bridge", ovs_check_bridge_delete, &ctx);
        if (ctx.error < 0)
                return ctx.error;

        /* Then delete orphaned ports that belonged to still-existing bridges */
        ovsdb_monitor_foreach(mon, "Port", ovs_check_port_delete, &ctx);
        if (ctx.error < 0)
                return ctx.error;

        return 0;
}

struct ovs_name_check {
        bool found;
        sd_id128_t uuid;  /* Set to the UUID when found */
};

/* Look up a row by name in the monitor cache via the O(1) by-name index, returning the
 * {found,uuid} shape the reconciler's call sites consume. */
static struct ovs_name_check ovs_lookup_by_name(OVSDBMonitor *mon, const char *table, const char *name) {
        struct ovs_name_check check = {};

        assert(table);

        if (mon && name && ovsdb_monitor_get_by_name(mon, table, name, &check.uuid, NULL) > 0)
                check.found = true;

        return check;
}

/* Invoke cb for each uuid string in an OVSDB uuid-set column value, in encounter order.
 * Accepts both the bare ["uuid","X"] singleton and the ["set",[["uuid","X"],...]] wrapper
 * (RFC 7047 §5.1 lets a max=unlimited column use either, though ovs-vswitchd always wraps).
 * Stops early and returns cb's value the first time cb returns non-zero; returns 0 otherwise.
 * Malformed shapes are skipped rather than rejected. */
static int ovs_uuid_set_foreach(
                sd_json_variant *col,
                int (*cb)(const char *uuid_str, void *userdata),
                void *userdata) {

        sd_json_variant *tag, *val;

        assert(cb);

        if (!col || !sd_json_variant_is_array(col) || sd_json_variant_elements(col) != 2)
                return 0;

        tag = sd_json_variant_by_index(col, 0);
        val = sd_json_variant_by_index(col, 1);
        if (!tag || !sd_json_variant_is_string(tag) || !val)
                return 0;

        if (streq(sd_json_variant_string(tag), "uuid") && sd_json_variant_is_string(val))
                return cb(sd_json_variant_string(val), userdata);

        if (!streq(sd_json_variant_string(tag), "set") || !sd_json_variant_is_array(val))
                return 0;

        for (size_t i = 0; i < sd_json_variant_elements(val); i++) {
                sd_json_variant *pair = sd_json_variant_by_index(val, i), *ptag, *puuid;
                int r;

                if (!pair || !sd_json_variant_is_array(pair) || sd_json_variant_elements(pair) != 2)
                        continue;

                ptag = sd_json_variant_by_index(pair, 0);
                puuid = sd_json_variant_by_index(pair, 1);
                if (!ptag || !sd_json_variant_is_string(ptag) ||
                    !streq(sd_json_variant_string(ptag), "uuid"))
                        continue;
                if (!puuid || !sd_json_variant_is_string(puuid))
                        continue;

                r = cb(sd_json_variant_string(puuid), userdata);
                if (r != 0)
                        return r;
        }

        return 0;
}

/* Callback for ovs_ensure_port_bridge_membership: scans Bridge rows, finds the one
 * whose `ports` set contains the target port UUID. Stores the bridge's name on match. */
struct ovs_find_port_bridge_ctx {
        char port_uuid_str[SD_ID128_UUID_STRING_MAX];  /* formatted once by the caller */
        const char *found_bridge_name;  /* aliases monitor cache; copy if retained */
};

static int ovs_uuid_match_cb(const char *uuid_str, void *userdata) {
        const char *target = ASSERT_PTR(userdata);
        return streq(uuid_str, target);  /* non-zero stops the walk on the first match */
}

static void ovs_find_port_bridge_cb(sd_id128_t uuid, sd_json_variant *row, void *userdata) {
        struct ovs_find_port_bridge_ctx *ctx = ASSERT_PTR(userdata);

        assert(row);

        if (ctx->found_bridge_name)
                return;  /* already matched */

        /* Bridge.ports is a uuid-set; compare our (pre-formatted, invariant) search key against
         * its atoms. ovs_uuid_match_cb returns non-zero on the first match. */
        if (ovs_uuid_set_foreach(sd_json_variant_by_key(row, "ports"),
                                 ovs_uuid_match_cb, ctx->port_uuid_str) != 0) {
                sd_json_variant *name = sd_json_variant_by_key(row, "name");
                if (name && sd_json_variant_is_string(name))
                        ctx->found_bridge_name = sd_json_variant_string(name);
        }
}

/* Ensure the Port identified by port_uuid is attached to desired_bridge.
 * If it's currently in a different bridge, emit mutate ops to remove it from the
 * old bridge and add it to the new one. No-op if already attached to desired_bridge. */
static int ovs_ensure_port_bridge_membership(
                Manager *m,
                sd_id128_t port_uuid,
                const char *desired_bridge,
                sd_json_variant **ops) {

        OVSDBMonitor *mon;
        struct ovs_find_port_bridge_ctx ctx;
        _cleanup_free_ char *current_bridge = NULL;
        int r;

        assert(m);
        assert(desired_bridge);
        assert(ops);

        mon = m->ovsdb ? ovsdb_client_get_monitor(m->ovsdb) : NULL;
        if (!mon)
                return 0;

        ctx = (struct ovs_find_port_bridge_ctx) {};
        sd_id128_to_uuid_string(port_uuid, ctx.port_uuid_str);
        ovsdb_monitor_foreach(mon, "Bridge", ovs_find_port_bridge_cb, &ctx);

        if (ctx.found_bridge_name && streq(ctx.found_bridge_name, desired_bridge))
                return 0;  /* already correctly attached */

        /* Copy name before dropping the cache alias (defensive against mid-op invalidation) */
        if (ctx.found_bridge_name) {
                current_bridge = strdup(ctx.found_bridge_name);
                if (!current_bridge)
                        return log_oom();

                r = ovs_emit_bridge_ports_mutate(current_bridge, port_uuid, "delete", ops);
                if (r < 0)
                        return r;
        }

        return ovs_emit_bridge_ports_mutate(desired_bridge, port_uuid, "insert", ops);
}

const char* ovs_monitor_get_bridge_fail_mode(Manager *m, const char *bridge_name) {
        OVSDBMonitor *mon;
        sd_json_variant *row, *fm;
        struct ovs_name_check check;

        assert(m);
        assert(bridge_name);

        mon = m->ovsdb ? ovsdb_client_get_monitor(m->ovsdb) : NULL;
        if (!mon)
                return NULL;

        check = ovs_lookup_by_name(mon, "Bridge", bridge_name);
        if (!check.found)
                return NULL;

        row = ovsdb_monitor_get(mon, "Bridge", check.uuid);
        if (!row)
                return NULL;

        fm = sd_json_variant_by_key(row, "fail_mode");
        if (!fm)
                return NULL;

        /* fail_mode is an optional (min=0, max=1) column: scalar string when set,
         * ["set", []] when unset. Only return when it's a plain string. */
        if (sd_json_variant_is_string(fm))
                return sd_json_variant_string(fm);

        return NULL;
}

/* Resolve a Port UUID in the monitor cache to its name */
static const char* ovs_monitor_port_name_by_uuid(OVSDBMonitor *mon, sd_id128_t uuid) {
        sd_json_variant *row, *name;

        row = ovsdb_monitor_get(mon, "Port", uuid);
        if (!row)
                return NULL;

        name = sd_json_variant_by_key(row, "name");
        if (!name || !sd_json_variant_is_string(name))
                return NULL;

        return sd_json_variant_string(name);
}

/* ovs_uuid_set_foreach callback: resolve each Port UUID to its name and append it (in order)
 * to the strv. Skips UUIDs not in the cache; stops with an error only on OOM. */
struct ovs_collect_port_names_ctx {
        OVSDBMonitor *mon;
        char ***ports;
        int error;
};

static int ovs_collect_port_name_cb(const char *uuid_str, void *userdata) {
        struct ovs_collect_port_names_ctx *c = ASSERT_PTR(userdata);
        sd_id128_t uuid;
        const char *name;
        int r;

        if (sd_id128_from_string(uuid_str, &uuid) < 0)
                return 0;  /* skip malformed atom, keep walking */

        name = ovs_monitor_port_name_by_uuid(c->mon, uuid);
        if (!name)
                return 0;

        r = strv_extend(c->ports, name);
        if (r < 0) {
                c->error = r;
                return 1;  /* stop the walk */
        }

        return 0;
}

int ovs_monitor_get_bridge_ports(Manager *m, const char *bridge_name, char ***ret_ports) {
        _cleanup_strv_free_ char **ports = NULL;
        OVSDBMonitor *mon;
        sd_json_variant *row;
        struct ovs_name_check check;

        assert(m);
        assert(bridge_name);
        assert(ret_ports);

        *ret_ports = NULL;

        mon = m->ovsdb ? ovsdb_client_get_monitor(m->ovsdb) : NULL;
        if (!mon)
                return 0;

        check = ovs_lookup_by_name(mon, "Bridge", bridge_name);
        if (!check.found)
                return 0;

        row = ovsdb_monitor_get(mon, "Bridge", check.uuid);
        if (!row)
                return 0;

        struct ovs_collect_port_names_ctx cctx = { .mon = mon, .ports = &ports };
        (void) ovs_uuid_set_foreach(sd_json_variant_by_key(row, "ports"), ovs_collect_port_name_cb, &cctx);
        if (cctx.error < 0)
                return cctx.error;

        *ret_ports = TAKE_PTR(ports);
        return 0;
}

/* RFC 7047 §5.1: named-uuid must match [a-zA-Z_][a-zA-Z0-9_]*
 *
 * Sanitizing the ifname collapses non-alnum/underscore chars to '_', so two
 * different interfaces (e.g. "eth0.1" and "eth0-1") could otherwise produce
 * the same uuid-name and collide inside one transact. Append an 8-hex-char
 * hash of the original ifname to disambiguate. */
#define OVS_UUID_HASH_KEY SD_ID128_MAKE(d4,11,a3,5b,7e,28,4f,c2,93,7a,0e,8d,ff,1b,c6,52)

static char* ovs_make_uuid_name(const char *prefix, const char *ifname) {
        char *name;
        uint64_t h;

        assert(prefix);
        assert(ifname);

        h = siphash24_string(ifname, OVS_UUID_HASH_KEY.bytes);

        if (asprintf(&name, "%s%s_%08" PRIx32, prefix, ifname, (uint32_t) (h & UINT32_MAX)) < 0)
                return NULL;

        for (char *p = name; *p; p++)
                if (!ascii_isalpha(*p) && !ascii_isdigit(*p) && *p != '_')
                        *p = '_';

        return name;
}

/* networkd-version is bumped when the on-wire schema we write to OVSDB changes,
 * so older networkd instances can detect rows written by a newer peer. */
#define OVS_NETWORKD_VERSION "1"

/* OVSDB Port.bond_{up,down}delay are integer milliseconds; ovs-vswitchd uses
 * a 32-bit signed counter internally. Clamp to that range to avoid sending
 * a value that the server will reject (or wrap on cast). */
#define OVS_BOND_DELAY_MAX_MS INT64_C(2147483647)

static int64_t ovs_bond_delay_clamp_ms(usec_t v) {
        return (int64_t) MIN(v / USEC_PER_MSEC, (usec_t) OVS_BOND_DELAY_MAX_MS);
}

/* Build the OVSDB encoding for an unset optional column: ["set", []].
 * UPDATE paths use this to reset columns when the corresponding config
 * setting was removed. */
static int ovs_build_empty_set(sd_json_variant **ret) {
        return sd_json_build(ret,
                        SD_JSON_BUILD_ARRAY(
                                JSON_BUILD_CONST_STRING("set"),
                                SD_JSON_BUILD_EMPTY_ARRAY));
}

/* Build a value for an OVSDB optional-string column: scalar string when set,
 * ["set", []] when NULL/unset. */
static int ovs_build_optional_string(const char *value, sd_json_variant **ret) {
        if (value)
                return sd_json_variant_new_string(ret, value);
        return ovs_build_empty_set(ret);
}

/* Build a value for an OVSDB optional-integer column. */
static int ovs_build_optional_int(int64_t value, bool present, sd_json_variant **ret) {
        if (present)
                return sd_json_variant_new_integer(ret, value);
        return ovs_build_empty_set(ret);
}

static int ovs_build_external_ids(const char *config_file, sd_json_variant **ret) {
        assert(ret);

        /* OVSDB map encoding: ["map", [["k1","v1"], ["k2","v2"]]] */
        return sd_json_build(
                        ret,
                        SD_JSON_BUILD_ARRAY(
                                JSON_BUILD_CONST_STRING("map"),
                                SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_ARRAY(
                                                JSON_BUILD_CONST_STRING("networkd-managed"),
                                                JSON_BUILD_CONST_STRING("true")),
                                        SD_JSON_BUILD_ARRAY(
                                                JSON_BUILD_CONST_STRING("networkd-config"),
                                                SD_JSON_BUILD_STRING(strempty(config_file))),
                                        SD_JSON_BUILD_ARRAY(
                                                JSON_BUILD_CONST_STRING("networkd-version"),
                                                SD_JSON_BUILD_STRING(OVS_NETWORKD_VERSION)))));
}

static int ovs_build_named_uuid_ref(const char *id, sd_json_variant **ret) {
        assert(id);
        assert(ret);

        return sd_json_build(
                        ret,
                        SD_JSON_BUILD_ARRAY(
                                JSON_BUILD_CONST_STRING("named-uuid"),
                                SD_JSON_BUILD_STRING(id)));
}

static int ovs_reconcile_bridge(Manager *m, NetDev *netdev, sd_json_variant **ops) {
        OVSBridge *b;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *external_ids = NULL, *iface_row = NULL,
                *iface_op = NULL, *iface_ref = NULL, *port_row = NULL, *port_op = NULL, *port_ref = NULL,
                *bridge_row = NULL, *bridge_op = NULL, *bridge_ref = NULL, *where = NULL, *mutations = NULL,
                *mutate_op = NULL;
        _cleanup_free_ char *iface_uuid_name = NULL, *port_uuid_name = NULL, *bridge_uuid_name = NULL;
        int r;

        assert(netdev);
        assert(ops);

        b = OVS_BRIDGE(netdev);

        /* If bridge already exists in monitor cache, UPDATE instead of INSERT */
        OVSDBMonitor *mon = ovsdb_client_get_monitor(m->ovsdb);
        if (mon) {
                struct ovs_name_check check = ovs_lookup_by_name(mon, "Bridge", netdev->ifname);
                if (check.found) {
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *update_row = NULL,
                                *update_where = NULL, *update_op = NULL, *update_ext = NULL,
                                *update_protocols = NULL;

                        log_netdev_debug(netdev, "OVS bridge '%s' already exists, updating", strna(netdev->ifname));

                        r = ovs_build_external_ids(netdev->filename, &update_ext);
                        if (r < 0)
                                return r;

                        /* Build protocols set: ["set", [...protos]] when set, ["set", []] when removed */
                        if (b->protocols) {
                                _cleanup_(sd_json_variant_unrefp) sd_json_variant *inner = NULL;
                                for (const OVSProtocol *p = b->protocols; *p != _OVS_PROTOCOL_INVALID; p++) {
                                        r = sd_json_variant_append_arrayb(&inner, SD_JSON_BUILD_STRING(ovs_protocol_to_string(*p)));
                                        if (r < 0)
                                                return r;
                                }
                                r = sd_json_build(&update_protocols,
                                                SD_JSON_BUILD_ARRAY(
                                                        JSON_BUILD_CONST_STRING("set"),
                                                        SD_JSON_BUILD_VARIANT(inner)));
                        } else
                                r = ovs_build_empty_set(&update_protocols);
                        if (r < 0)
                                return r;

                        /* Optional columns: emit unconditionally so removed config values
                         * reset the OVSDB column instead of leaving stale state behind. */
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *fail_mode_v = NULL,
                                *datapath_id_v = NULL;

                        r = ovs_build_optional_string(ovs_bridge_fail_mode_to_string(b->fail_mode), &fail_mode_v);
                        if (r < 0)
                                return r;
                        r = ovs_build_optional_string(b->datapath_id, &datapath_id_v);
                        if (r < 0)
                                return r;

                        /* Tristate columns (stp_enable, rstp_enable, mcast_snooping_enable)
                         * and `datapath_type`: only emit when the operator explicitly set them.
                         * Treating an unset tristate (-1) as "false" or unset string as "" on
                         * UPDATE would clobber values set out-of-band (ovs-vsctl, OVN, OpenStack)
                         * on every reload — INSERT path mirrors this. */
                        r = sd_json_buildo(
                                        &update_row,
                                        SD_JSON_BUILD_PAIR_VARIANT("fail_mode", fail_mode_v),
                                        SD_JSON_BUILD_PAIR_CONDITION(b->stp >= 0, "stp_enable", SD_JSON_BUILD_BOOLEAN(b->stp > 0)),
                                        SD_JSON_BUILD_PAIR_CONDITION(b->rstp >= 0, "rstp_enable", SD_JSON_BUILD_BOOLEAN(b->rstp > 0)),
                                        SD_JSON_BUILD_PAIR_CONDITION(b->mcast_snooping >= 0, "mcast_snooping_enable", SD_JSON_BUILD_BOOLEAN(b->mcast_snooping > 0)),
                                        SD_JSON_BUILD_PAIR_CONDITION(!!b->datapath_type, "datapath_type", SD_JSON_BUILD_STRING(strempty(b->datapath_type))),
                                        SD_JSON_BUILD_PAIR_VARIANT("protocols", update_protocols),
                                        SD_JSON_BUILD_PAIR_VARIANT("datapath_id", datapath_id_v),
                                        SD_JSON_BUILD_PAIR_VARIANT("external_ids", update_ext));
                        if (r < 0)
                                return r;

                        r = ovsdb_where_uuid(check.uuid, &update_where);
                        if (r < 0)
                                return r;

                        r = ovsdb_op_update("Bridge", update_where, update_row, &update_op);
                        if (r < 0)
                                return r;

                        r = sd_json_variant_append_array(ops, update_op);
                        if (r < 0)
                                return r;

                        /* READY transition deferred: kernel-backed kinds go via set_ifindex
                         * on RTM_NEWLINK; non-kernel-backed via ovs_reconcile_done on ACK. */
                        return 0;
                }
        }

        /* uuid-names for cross-referencing within the transact */
        iface_uuid_name = ovs_make_uuid_name("iface_", netdev->ifname);
        if (!iface_uuid_name)
                return log_oom();

        port_uuid_name = ovs_make_uuid_name("port_", netdev->ifname);
        if (!port_uuid_name)
                return log_oom();

        bridge_uuid_name = ovs_make_uuid_name("br_", netdev->ifname);
        if (!bridge_uuid_name)
                return log_oom();

        /* Build external_ids map */
        r = ovs_build_external_ids(netdev->filename, &external_ids);
        if (r < 0)
                return log_netdev_warning_errno(netdev, r, "Failed to build external_ids: %m");

        /* 1. Insert Interface (name=bridge_name, type="internal") */
        r = sd_json_buildo(
                        &iface_row,
                        SD_JSON_BUILD_PAIR_STRING("name", netdev->ifname),
                        SD_JSON_BUILD_PAIR_STRING("type", "internal"),
                        SD_JSON_BUILD_PAIR_VARIANT("external_ids", external_ids));
        if (r < 0)
                return log_netdev_warning_errno(netdev, r, "Failed to build Interface row: %m");

        r = ovsdb_op_insert("Interface", iface_uuid_name, iface_row, &iface_op);
        if (r < 0)
                return r;

        r = sd_json_variant_append_array(ops, iface_op);
        if (r < 0)
                return r;

        /* 2. Insert Port (name=bridge_name, interfaces=ref to iface) */
        r = ovs_build_named_uuid_ref(iface_uuid_name, &iface_ref);
        if (r < 0)
                return r;

        r = sd_json_buildo(
                        &port_row,
                        SD_JSON_BUILD_PAIR_STRING("name", netdev->ifname),
                        SD_JSON_BUILD_PAIR_VARIANT("interfaces", iface_ref),
                        SD_JSON_BUILD_PAIR_VARIANT("external_ids", external_ids));
        if (r < 0)
                return log_netdev_warning_errno(netdev, r, "Failed to build Port row: %m");

        r = ovsdb_op_insert("Port", port_uuid_name, port_row, &port_op);
        if (r < 0)
                return r;

        r = sd_json_variant_append_array(ops, port_op);
        if (r < 0)
                return r;

        /* 3. Insert Bridge */
        r = ovs_build_named_uuid_ref(port_uuid_name, &port_ref);
        if (r < 0)
                return r;

        /* Build protocols set if present */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *protocols_set = NULL;
        if (b->protocols) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *inner = NULL;
                for (const OVSProtocol *p = b->protocols; *p != _OVS_PROTOCOL_INVALID; p++) {
                        r = sd_json_variant_append_arrayb(&inner, SD_JSON_BUILD_STRING(ovs_protocol_to_string(*p)));
                        if (r < 0)
                                return r;
                }
                r = sd_json_build(&protocols_set,
                        SD_JSON_BUILD_ARRAY(
                                JSON_BUILD_CONST_STRING("set"),
                                SD_JSON_BUILD_VARIANT(inner)));
                if (r < 0)
                        return r;
        }

        r = sd_json_buildo(
                        &bridge_row,
                        SD_JSON_BUILD_PAIR_STRING("name", netdev->ifname),
                        SD_JSON_BUILD_PAIR_VARIANT("ports", port_ref),
                        SD_JSON_BUILD_PAIR_CONDITION(b->fail_mode >= 0, "fail_mode", SD_JSON_BUILD_STRING(ovs_bridge_fail_mode_to_string(b->fail_mode))),
                        SD_JSON_BUILD_PAIR_CONDITION(b->stp >= 0, "stp_enable", SD_JSON_BUILD_BOOLEAN(b->stp > 0)),
                        SD_JSON_BUILD_PAIR_CONDITION(b->rstp >= 0, "rstp_enable", SD_JSON_BUILD_BOOLEAN(b->rstp > 0)),
                        SD_JSON_BUILD_PAIR_CONDITION(b->mcast_snooping >= 0, "mcast_snooping_enable", SD_JSON_BUILD_BOOLEAN(b->mcast_snooping > 0)),
                        SD_JSON_BUILD_PAIR_CONDITION(!!b->datapath_type, "datapath_type", SD_JSON_BUILD_STRING(strempty(b->datapath_type))),
                        SD_JSON_BUILD_PAIR_CONDITION(!!protocols_set, "protocols", SD_JSON_BUILD_VARIANT(protocols_set)),
                        SD_JSON_BUILD_PAIR_CONDITION(!!b->datapath_id, "datapath_id", SD_JSON_BUILD_STRING(b->datapath_id)),
                        SD_JSON_BUILD_PAIR_VARIANT("external_ids", external_ids));
        if (r < 0)
                return log_netdev_warning_errno(netdev, r, "Failed to build Bridge row: %m");

        r = ovsdb_op_insert("Bridge", bridge_uuid_name, bridge_row, &bridge_op);
        if (r < 0)
                return r;

        r = sd_json_variant_append_array(ops, bridge_op);
        if (r < 0)
                return r;

        /* 4. Mutate Open_vSwitch: bridges += ["named-uuid", "br-<name>"] */
        r = ovs_build_named_uuid_ref(bridge_uuid_name, &bridge_ref);
        if (r < 0)
                return r;

        r = ovsdb_where_all(&where);
        if (r < 0)
                return r;

        /* mutations: [["bridges", "insert", ["set", [ref]]]] */
        r = sd_json_build(
                        &mutations,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_ARRAY(
                                        JSON_BUILD_CONST_STRING("bridges"),
                                        JSON_BUILD_CONST_STRING("insert"),
                                        SD_JSON_BUILD_ARRAY(
                                                JSON_BUILD_CONST_STRING("set"),
                                                SD_JSON_BUILD_ARRAY(
                                                        SD_JSON_BUILD_VARIANT(bridge_ref))))));
        if (r < 0)
                return r;

        r = ovsdb_op_mutate("Open_vSwitch", where, mutations, &mutate_op);
        if (r < 0)
                return r;

        r = sd_json_variant_append_array(ops, mutate_op);
        if (r < 0)
                return r;

        log_netdev_debug(netdev, "OVS bridge queued for reconciliation");
        return 0;
}

static int ovs_build_vlan_set(const char *trunks_str, sd_json_variant **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *ids = NULL;
        int r;

        assert(trunks_str);
        assert(ret);

        /* Parse comma-separated VLAN IDs into ["set", [id1, id2, ...]] */
        for (const char *p = trunks_str;;) {
                _cleanup_free_ char *word = NULL;
                uint16_t vid;

                r = extract_first_word(&p, &word, ",", 0);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                r = parse_vlanid(word, &vid);
                if (r < 0)
                        return r;

                r = sd_json_variant_append_arrayb(&ids, SD_JSON_BUILD_INTEGER(vid));
                if (r < 0)
                        return r;
        }

        if (!ids) {
                /* Empty trunks list — caller should skip the column */
                *ret = NULL;
                return 0;
        }

        return sd_json_build(
                        ret,
                        SD_JSON_BUILD_ARRAY(
                                JSON_BUILD_CONST_STRING("set"),
                                SD_JSON_BUILD_VARIANT(ids)));
}

/* Collect concrete interface names from Links whose effective .network references this bond.
 * Iterating Links (not Networks.match.ifname patterns) correctly expands globs and respects
 * networkd's matcher — link->network is the one .network that won for that interface. */
static int ovs_collect_bond_members(Manager *m, const char *bond_name, char ***ret_members) {
        _cleanup_strv_free_ char **members = NULL;
        Link *link;
        int r;

        assert(m);
        assert(bond_name);
        assert(ret_members);

        HASHMAP_FOREACH(link, m->links_by_index) {
                if (!link->network)
                        continue;
                if (!link->network->ovs_bond_name)
                        continue;
                if (!streq(link->network->ovs_bond_name, bond_name))
                        continue;
                if (!link->ifname)
                        continue;
                if (strv_contains(members, link->ifname))
                        continue;

                r = strv_extend(&members, link->ifname);
                if (r < 0)
                        return r;
        }

        *ret_members = TAKE_PTR(members);
        return 0;
}

static int ovs_reconcile_bond_port(
                Manager *m,
                NetDev *netdev,
                OVSPort *p,
                char **members,
                Set *doomed_ports,  /* names of Ports being deleted this reconcile (borrowed) */
                sd_json_variant **ops) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *external_ids = NULL, *iface_set = NULL,
                *port_row = NULL, *port_op = NULL, *port_ref = NULL, *where = NULL, *mutations = NULL,
                *mutate_op = NULL, *trunks_set = NULL;
        _cleanup_free_ char *port_uuid_name = NULL;
        int r;

        assert(netdev);
        assert(p);
        assert(members);
        assert(ops);

        /* If bond port already exists in monitor cache, UPDATE */
        OVSDBMonitor *mon = ovsdb_client_get_monitor(m->ovsdb);
        if (mon) {
                struct ovs_name_check check = ovs_lookup_by_name(mon, "Port", netdev->ifname);
                if (check.found) {
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *update_row = NULL,
                                *update_where = NULL, *update_op = NULL, *update_ext = NULL,
                                *update_trunks = NULL, *update_iface_refs = NULL, *update_iface_set = NULL;

                        log_netdev_debug(netdev, "OVS bond '%s' already exists, updating", strna(netdev->ifname));

                        r = ovs_build_external_ids(netdev->filename, &update_ext);
                        if (r < 0)
                                return r;

                        if (p->trunks) {
                                r = ovs_build_vlan_set(p->trunks, &update_trunks);
                                if (r < 0)
                                        return r;
                        }

                        /* Build interfaces set: reuse existing Interface UUIDs from cache,
                         * INSERT new Interface rows for members not yet in OVSDB. */
                        STRV_FOREACH(member, members) {
                                _cleanup_(sd_json_variant_unrefp) sd_json_variant *iface_ref = NULL;
                                struct ovs_name_check ifcheck = ovs_lookup_by_name(mon, "Interface", *member);

                                /* A member migrating from a standalone OVSBridge= attachment to this
                                 * bond has its old Port (and, by cascade, its same-named Interface)
                                 * DELETEd in Phase 0 of this very transact. Reusing that Interface's
                                 * UUID here would reference a row being deleted in the same atomic
                                 * transact — OVSDB rejects the dangling reference, rolls everything
                                 * back, and the cache never advances, wedging reconciliation forever.
                                 * Treat such members as new and INSERT a fresh Interface instead
                                 * (Phase 0 deletes are ordered before these Phase 2 inserts). */
                                if (ifcheck.found && !set_contains(doomed_ports, *member)) {
                                        /* Reuse existing Interface by UUID */
                                        r = ovs_build_uuid_ref(ifcheck.uuid, &iface_ref);
                                        if (r < 0)
                                                return r;
                                } else {
                                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *iface_row = NULL,
                                                *iface_op = NULL;
                                        _cleanup_free_ char *iface_uuid_name = NULL;

                                        iface_uuid_name = ovs_make_uuid_name("iface_", *member);
                                        if (!iface_uuid_name)
                                                return log_oom();

                                        r = sd_json_buildo(
                                                        &iface_row,
                                                        SD_JSON_BUILD_PAIR_STRING("name", *member),
                                                        SD_JSON_BUILD_PAIR_STRING("type", ""),
                                                        SD_JSON_BUILD_PAIR_VARIANT("external_ids", update_ext));
                                        if (r < 0)
                                                return r;

                                        r = ovsdb_op_insert("Interface", iface_uuid_name, iface_row, &iface_op);
                                        if (r < 0)
                                                return r;

                                        r = sd_json_variant_append_array(ops, iface_op);
                                        if (r < 0)
                                                return r;

                                        r = ovs_build_named_uuid_ref(iface_uuid_name, &iface_ref);
                                        if (r < 0)
                                                return r;
                                }

                                r = sd_json_variant_append_array(&update_iface_refs, iface_ref);
                                if (r < 0)
                                        return r;
                        }

                        r = sd_json_build(
                                        &update_iface_set,
                                        SD_JSON_BUILD_ARRAY(
                                                JSON_BUILD_CONST_STRING("set"),
                                                SD_JSON_BUILD_VARIANT(update_iface_refs)));
                        if (r < 0)
                                return r;

                        /* Always emit optional columns so removed config resets the OVSDB column */
                        if (!update_trunks) {
                                r = ovs_build_empty_set(&update_trunks);
                                if (r < 0)
                                        return r;
                        }

                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *tag_v = NULL, *vlan_mode_v = NULL,
                                *lacp_v = NULL, *bond_mode_v = NULL;

                        r = ovs_build_optional_int(p->tag, p->tag != VLANID_INVALID, &tag_v);
                        if (r < 0)
                                return r;
                        r = ovs_build_optional_string(ovs_port_vlan_mode_to_string(p->vlan_mode), &vlan_mode_v);
                        if (r < 0)
                                return r;
                        r = ovs_build_optional_string(ovs_lacp_to_string(p->lacp), &lacp_v);
                        if (r < 0)
                                return r;
                        r = ovs_build_optional_string(ovs_bond_mode_to_string(p->bond_mode), &bond_mode_v);
                        if (r < 0)
                                return r;

                        /* Bond delays: emit only when the operator explicitly set them, mirroring
                         * the INSERT path. Always-emit-with-zero clobbers values set by ovs-vsctl
                         * or OVN on every reload. */
                        r = sd_json_buildo(
                                        &update_row,
                                        SD_JSON_BUILD_PAIR_VARIANT("interfaces", update_iface_set),
                                        SD_JSON_BUILD_PAIR_VARIANT("tag", tag_v),
                                        SD_JSON_BUILD_PAIR_VARIANT("vlan_mode", vlan_mode_v),
                                        SD_JSON_BUILD_PAIR_VARIANT("trunks", update_trunks),
                                        SD_JSON_BUILD_PAIR_VARIANT("lacp", lacp_v),
                                        SD_JSON_BUILD_PAIR_VARIANT("bond_mode", bond_mode_v),
                                        SD_JSON_BUILD_PAIR_CONDITION(p->bond_updelay != USEC_INFINITY,
                                                "bond_updelay", SD_JSON_BUILD_INTEGER(ovs_bond_delay_clamp_ms(p->bond_updelay))),
                                        SD_JSON_BUILD_PAIR_CONDITION(p->bond_downdelay != USEC_INFINITY,
                                                "bond_downdelay", SD_JSON_BUILD_INTEGER(ovs_bond_delay_clamp_ms(p->bond_downdelay))),
                                        SD_JSON_BUILD_PAIR_VARIANT("external_ids", update_ext));
                        if (r < 0)
                                return r;

                        r = ovsdb_where_uuid(check.uuid, &update_where);
                        if (r < 0)
                                return r;

                        r = ovsdb_op_update("Port", update_where, update_row, &update_op);
                        if (r < 0)
                                return r;

                        r = sd_json_variant_append_array(ops, update_op);
                        if (r < 0)
                                return r;

                        /* If the parent bridge changed, move the Port between bridges */
                        r = ovs_ensure_port_bridge_membership(m, check.uuid, p->bridge, ops);
                        if (r < 0)
                                return r;

                        /* READY transition deferred to ovs_reconcile_done on ACK */
                        return 0;
                }
        }

        port_uuid_name = ovs_make_uuid_name("port_", netdev->ifname);
        if (!port_uuid_name)
                return log_oom();

        r = ovs_build_external_ids(netdev->filename, &external_ids);
        if (r < 0)
                return log_netdev_warning_errno(netdev, r, "Failed to build external_ids: %m");

        /* 1. Insert Interface rows for each bond member (type="" = system) */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *iface_refs_inner = NULL;

        STRV_FOREACH(member, members) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *iface_row = NULL, *iface_op = NULL,
                        *iface_ref = NULL;
                _cleanup_free_ char *iface_uuid_name = NULL;

                iface_uuid_name = ovs_make_uuid_name("iface_", *member);
                if (!iface_uuid_name)
                        return log_oom();

                r = sd_json_buildo(
                                &iface_row,
                                SD_JSON_BUILD_PAIR_STRING("name", *member),
                                SD_JSON_BUILD_PAIR_STRING("type", ""),
                                SD_JSON_BUILD_PAIR_VARIANT("external_ids", external_ids));
                if (r < 0)
                        return r;

                r = ovsdb_op_insert("Interface", iface_uuid_name, iface_row, &iface_op);
                if (r < 0)
                        return r;

                r = sd_json_variant_append_array(ops, iface_op);
                if (r < 0)
                        return r;

                r = ovs_build_named_uuid_ref(iface_uuid_name, &iface_ref);
                if (r < 0)
                        return r;

                r = sd_json_variant_append_array(&iface_refs_inner, iface_ref);
                if (r < 0)
                        return r;
        }

        r = sd_json_build(
                        &iface_set,
                        SD_JSON_BUILD_ARRAY(
                                JSON_BUILD_CONST_STRING("set"),
                                SD_JSON_BUILD_VARIANT(iface_refs_inner)));
        if (r < 0)
                return r;

        /* 2. Insert Port with bond settings */
        if (p->trunks) {
                r = ovs_build_vlan_set(p->trunks, &trunks_set);
                if (r < 0)
                        return log_netdev_warning_errno(netdev, r, "Failed to parse trunks: %m");
        }

        r = sd_json_buildo(
                        &port_row,
                        SD_JSON_BUILD_PAIR_STRING("name", netdev->ifname),
                        SD_JSON_BUILD_PAIR_VARIANT("interfaces", iface_set),
                        SD_JSON_BUILD_PAIR_CONDITION(p->tag != VLANID_INVALID, "tag", SD_JSON_BUILD_INTEGER(p->tag)),
                        SD_JSON_BUILD_PAIR_CONDITION(p->vlan_mode >= 0, "vlan_mode", SD_JSON_BUILD_STRING(ovs_port_vlan_mode_to_string(p->vlan_mode))),
                        SD_JSON_BUILD_PAIR_CONDITION(!!trunks_set, "trunks", SD_JSON_BUILD_VARIANT(trunks_set)),
                        SD_JSON_BUILD_PAIR_CONDITION(p->lacp >= 0, "lacp", SD_JSON_BUILD_STRING(ovs_lacp_to_string(p->lacp))),
                        SD_JSON_BUILD_PAIR_CONDITION(p->bond_mode >= 0, "bond_mode", SD_JSON_BUILD_STRING(ovs_bond_mode_to_string(p->bond_mode))),
                        SD_JSON_BUILD_PAIR_CONDITION(p->bond_updelay != USEC_INFINITY, "bond_updelay", SD_JSON_BUILD_INTEGER(ovs_bond_delay_clamp_ms(p->bond_updelay))),
                        SD_JSON_BUILD_PAIR_CONDITION(p->bond_downdelay != USEC_INFINITY, "bond_downdelay", SD_JSON_BUILD_INTEGER(ovs_bond_delay_clamp_ms(p->bond_downdelay))),
                        SD_JSON_BUILD_PAIR_VARIANT("external_ids", external_ids));
        if (r < 0)
                return log_netdev_warning_errno(netdev, r, "Failed to build Port row: %m");

        r = ovsdb_op_insert("Port", port_uuid_name, port_row, &port_op);
        if (r < 0)
                return r;

        r = sd_json_variant_append_array(ops, port_op);
        if (r < 0)
                return r;

        /* 3. Mutate parent bridge: ports += ref */
        r = ovs_build_named_uuid_ref(port_uuid_name, &port_ref);
        if (r < 0)
                return r;

        r = sd_json_build(
                        &where,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_ARRAY(
                                        JSON_BUILD_CONST_STRING("name"),
                                        JSON_BUILD_CONST_STRING("=="),
                                        SD_JSON_BUILD_STRING(p->bridge))));
        if (r < 0)
                return r;

        r = sd_json_build(
                        &mutations,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_ARRAY(
                                        JSON_BUILD_CONST_STRING("ports"),
                                        JSON_BUILD_CONST_STRING("insert"),
                                        SD_JSON_BUILD_ARRAY(
                                                JSON_BUILD_CONST_STRING("set"),
                                                SD_JSON_BUILD_ARRAY(
                                                        SD_JSON_BUILD_VARIANT(port_ref))))));
        if (r < 0)
                return r;

        r = ovsdb_op_mutate("Bridge", where, mutations, &mutate_op);
        if (r < 0)
                return r;

        r = sd_json_variant_append_array(ops, mutate_op);
        if (r < 0)
                return r;

        log_netdev_debug(netdev, "OVS bond port '%s' queued for reconciliation (%zu members)",
                         strna(netdev->ifname), strv_length(members));
        return 0;
}

static int ovs_reconcile_port(Manager *m, NetDev *netdev, Set *doomed_ports, sd_json_variant **ops) {
        OVSPort *p;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *external_ids = NULL, *iface_row = NULL,
                *iface_op = NULL, *iface_ref = NULL, *port_row = NULL, *port_op = NULL, *port_ref = NULL,
                *where = NULL, *mutations = NULL, *mutate_op = NULL, *trunks_set = NULL;
        _cleanup_free_ char *iface_uuid_name = NULL, *port_uuid_name = NULL;
        const char *iface_type;
        int r;

        assert(netdev);
        assert(ops);

        p = OVS_PORT(netdev);

        if (p->type == OVS_PORT_TYPE_BOND) {
                _cleanup_strv_free_ char **bond_members = NULL;

                r = ovs_collect_bond_members(m, netdev->ifname, &bond_members);
                if (r < 0)
                        return log_netdev_warning_errno(netdev, r, "Failed to collect bond members: %m");

                if (strv_isempty(bond_members)) {
                        /* OVSDB Port.interfaces has min=1, so a bond with no members
                         * cannot legally exist. If a Port row remains in OVSDB from an
                         * earlier reconcile, delete it now so stale members don't linger. */
                        OVSDBMonitor *mon = ovsdb_client_get_monitor(m->ovsdb);
                        if (mon) {
                                struct ovs_name_check check = ovs_lookup_by_name(mon, "Port", netdev->ifname);
                                if (check.found) {
                                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *del_where = NULL,
                                                *delete_op = NULL;

                                        log_netdev_debug(netdev, "OVS bond '%s' has no member interfaces, deleting stale Port row",
                                                         strna(netdev->ifname));

                                        /* Unlink from whatever bridge currently owns it (strong ref).
                                         * Use the all-bridges mutate rather than matching p->bridge by
                                         * name: if Bridge= changed in the same edit that emptied the
                                         * bond, the port still lives in the old bridge, and a
                                         * name-matched mutate would miss it and leave a dangling
                                         * strong reference that rolls back the whole transact. */
                                        r = ovs_emit_bridge_ports_mutate(/* bridge_name= */ NULL, check.uuid, "delete", ops);
                                        if (r < 0)
                                                return r;

                                        /* Then drop the Port row */
                                        r = ovsdb_where_uuid(check.uuid, &del_where);
                                        if (r < 0)
                                                return r;

                                        r = ovsdb_op_delete("Port", del_where, &delete_op);
                                        if (r < 0)
                                                return r;

                                        r = sd_json_variant_append_array(ops, delete_op);
                                        if (r < 0)
                                                return r;
                                } else
                                        log_netdev_debug(netdev, "OVS bond '%s' has no member interfaces, skipping",
                                                         strna(netdev->ifname));
                        }
                        return 0;
                }

                return ovs_reconcile_bond_port(m, netdev, p, bond_members, doomed_ports, ops);
        }

        /* If port already exists in monitor cache, UPDATE instead of INSERT */
        OVSDBMonitor *mon = ovsdb_client_get_monitor(m->ovsdb);
        if (mon) {
                struct ovs_name_check check = ovs_lookup_by_name(mon, "Port", netdev->ifname);
                if (check.found) {
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *update_row = NULL,
                                *update_where = NULL, *update_op = NULL, *update_ext = NULL,
                                *update_trunks = NULL;

                        log_netdev_debug(netdev, "OVS port '%s' already exists, updating", strna(netdev->ifname));

                        r = ovs_build_external_ids(netdev->filename, &update_ext);
                        if (r < 0)
                                return r;

                        if (p->trunks) {
                                r = ovs_build_vlan_set(p->trunks, &update_trunks);
                                if (r < 0)
                                        return log_netdev_warning_errno(netdev, r, "Failed to parse trunks '%s': %m", p->trunks);
                        }
                        if (!update_trunks) {
                                r = ovs_build_empty_set(&update_trunks);
                                if (r < 0)
                                        return r;
                        }

                        /* Always emit optional columns so removed config resets the OVSDB column */
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *tag_v = NULL, *vlan_mode_v = NULL;

                        r = ovs_build_optional_int(p->tag, p->tag != VLANID_INVALID, &tag_v);
                        if (r < 0)
                                return r;
                        r = ovs_build_optional_string(ovs_port_vlan_mode_to_string(p->vlan_mode), &vlan_mode_v);
                        if (r < 0)
                                return r;

                        r = sd_json_buildo(
                                        &update_row,
                                        SD_JSON_BUILD_PAIR_VARIANT("tag", tag_v),
                                        SD_JSON_BUILD_PAIR_VARIANT("vlan_mode", vlan_mode_v),
                                        SD_JSON_BUILD_PAIR_VARIANT("trunks", update_trunks),
                                        SD_JSON_BUILD_PAIR_VARIANT("external_ids", update_ext));
                        if (r < 0)
                                return r;

                        r = ovsdb_where_uuid(check.uuid, &update_where);
                        if (r < 0)
                                return r;

                        r = ovsdb_op_update("Port", update_where, update_row, &update_op);
                        if (r < 0)
                                return r;

                        r = sd_json_variant_append_array(ops, update_op);
                        if (r < 0)
                                return r;

                        /* Always reconcile Interface.type and Interface.options to support
                         * Type=internal <-> Type=patch transitions. For internal ports we
                         * clear options to ["map", []]; for patch ports we set options:peer.
                         * Without this, changing Type= after creation leaves stale OVSDB
                         * Interface state (old type or stale patch peer). */
                        {
                                struct ovs_name_check ifcheck = ovs_lookup_by_name(mon, "Interface", netdev->ifname);
                                if (ifcheck.found) {
                                        _cleanup_(sd_json_variant_unrefp) sd_json_variant
                                                *iface_options = NULL, *iface_row_update = NULL,
                                                *iface_where_update = NULL, *iface_update_op = NULL;
                                        const char *iface_type_now;

                                        if (p->type == OVS_PORT_TYPE_PATCH && p->peer_port) {
                                                iface_type_now = "patch";
                                                r = sd_json_build(
                                                                &iface_options,
                                                                SD_JSON_BUILD_ARRAY(
                                                                        JSON_BUILD_CONST_STRING("map"),
                                                                        SD_JSON_BUILD_ARRAY(
                                                                                SD_JSON_BUILD_ARRAY(
                                                                                        JSON_BUILD_CONST_STRING("peer"),
                                                                                        SD_JSON_BUILD_STRING(p->peer_port)))));
                                        } else {
                                                /* internal port (or patch with missing peer) — clear options */
                                                iface_type_now = "internal";
                                                r = sd_json_build(
                                                                &iface_options,
                                                                SD_JSON_BUILD_ARRAY(
                                                                        JSON_BUILD_CONST_STRING("map"),
                                                                        SD_JSON_BUILD_EMPTY_ARRAY));
                                        }
                                        if (r < 0)
                                                return r;

                                        r = sd_json_buildo(
                                                        &iface_row_update,
                                                        SD_JSON_BUILD_PAIR_STRING("type", iface_type_now),
                                                        SD_JSON_BUILD_PAIR_VARIANT("options", iface_options),
                                                        SD_JSON_BUILD_PAIR_VARIANT("external_ids", update_ext));
                                        if (r < 0)
                                                return r;

                                        r = ovsdb_where_uuid(ifcheck.uuid, &iface_where_update);
                                        if (r < 0)
                                                return r;

                                        r = ovsdb_op_update("Interface", iface_where_update, iface_row_update, &iface_update_op);
                                        if (r < 0)
                                                return r;

                                        r = sd_json_variant_append_array(ops, iface_update_op);
                                        if (r < 0)
                                                return r;
                                }
                        }

                        /* If the parent bridge changed, move the Port between bridges */
                        r = ovs_ensure_port_bridge_membership(m, check.uuid, p->bridge, ops);
                        if (r < 0)
                                return r;

                        /* READY transition deferred: internal via set_ifindex on RTM_NEWLINK,
                         * patch via ovs_reconcile_done on ACK. */
                        return 0;
                }
        }

        iface_uuid_name = ovs_make_uuid_name("iface_", netdev->ifname);
        if (!iface_uuid_name)
                return log_oom();

        port_uuid_name = ovs_make_uuid_name("port_", netdev->ifname);
        if (!port_uuid_name)
                return log_oom();

        r = ovs_build_external_ids(netdev->filename, &external_ids);
        if (r < 0)
                return log_netdev_warning_errno(netdev, r, "Failed to build external_ids: %m");

        /* Determine interface type from port type */
        switch (p->type) {
        case OVS_PORT_TYPE_INTERNAL:
                iface_type = "internal";
                break;
        case OVS_PORT_TYPE_PATCH:
                iface_type = "patch";
                break;
        default:
                assert_not_reached();
        }

        /* 1. Insert Interface */
        {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *iface_options = NULL;

                /* Patch ports require options: {"peer": "<name>"} */
                if (p->type == OVS_PORT_TYPE_PATCH && p->peer_port) {
                        r = sd_json_build(
                                        &iface_options,
                                        SD_JSON_BUILD_ARRAY(
                                                JSON_BUILD_CONST_STRING("map"),
                                                SD_JSON_BUILD_ARRAY(
                                                        SD_JSON_BUILD_ARRAY(
                                                                JSON_BUILD_CONST_STRING("peer"),
                                                                SD_JSON_BUILD_STRING(p->peer_port)))));
                        if (r < 0)
                                return log_netdev_warning_errno(netdev, r, "Failed to build patch options: %m");
                }

                r = sd_json_buildo(
                                &iface_row,
                                SD_JSON_BUILD_PAIR_STRING("name", netdev->ifname),
                                SD_JSON_BUILD_PAIR_STRING("type", iface_type),
                                SD_JSON_BUILD_PAIR_CONDITION(!!iface_options, "options", SD_JSON_BUILD_VARIANT(iface_options)),
                                SD_JSON_BUILD_PAIR_VARIANT("external_ids", external_ids));
                if (r < 0)
                        return log_netdev_warning_errno(netdev, r, "Failed to build Interface row: %m");
        }

        r = ovsdb_op_insert("Interface", iface_uuid_name, iface_row, &iface_op);
        if (r < 0)
                return r;

        r = sd_json_variant_append_array(ops, iface_op);
        if (r < 0)
                return r;

        /* 2. Insert Port */
        r = ovs_build_named_uuid_ref(iface_uuid_name, &iface_ref);
        if (r < 0)
                return r;

        if (p->trunks) {
                r = ovs_build_vlan_set(p->trunks, &trunks_set);
                if (r < 0)
                        return log_netdev_warning_errno(netdev, r, "Failed to parse trunks '%s': %m", p->trunks);
        }

        r = sd_json_buildo(
                        &port_row,
                        SD_JSON_BUILD_PAIR_STRING("name", netdev->ifname),
                        SD_JSON_BUILD_PAIR_VARIANT("interfaces", iface_ref),
                        SD_JSON_BUILD_PAIR_CONDITION(p->tag != VLANID_INVALID, "tag", SD_JSON_BUILD_INTEGER(p->tag)),
                        SD_JSON_BUILD_PAIR_CONDITION(p->vlan_mode >= 0, "vlan_mode", SD_JSON_BUILD_STRING(ovs_port_vlan_mode_to_string(p->vlan_mode))),
                        SD_JSON_BUILD_PAIR_CONDITION(!!trunks_set, "trunks", SD_JSON_BUILD_VARIANT(trunks_set)),
                        SD_JSON_BUILD_PAIR_VARIANT("external_ids", external_ids));
        if (r < 0)
                return log_netdev_warning_errno(netdev, r, "Failed to build Port row: %m");

        r = ovsdb_op_insert("Port", port_uuid_name, port_row, &port_op);
        if (r < 0)
                return r;

        r = sd_json_variant_append_array(ops, port_op);
        if (r < 0)
                return r;

        /* 3. Mutate parent bridge: ports += ["named-uuid", "port-<name>"] */
        r = ovs_build_named_uuid_ref(port_uuid_name, &port_ref);
        if (r < 0)
                return r;

        /* Match the parent bridge by name */
        r = sd_json_build(
                        &where,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_ARRAY(
                                        JSON_BUILD_CONST_STRING("name"),
                                        JSON_BUILD_CONST_STRING("=="),
                                        SD_JSON_BUILD_STRING(p->bridge))));
        if (r < 0)
                return r;

        r = sd_json_build(
                        &mutations,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_ARRAY(
                                        JSON_BUILD_CONST_STRING("ports"),
                                        JSON_BUILD_CONST_STRING("insert"),
                                        SD_JSON_BUILD_ARRAY(
                                                JSON_BUILD_CONST_STRING("set"),
                                                SD_JSON_BUILD_ARRAY(
                                                        SD_JSON_BUILD_VARIANT(port_ref))))));
        if (r < 0)
                return r;

        r = ovsdb_op_mutate("Bridge", where, mutations, &mutate_op);
        if (r < 0)
                return r;

        r = sd_json_variant_append_array(ops, mutate_op);
        if (r < 0)
                return r;

        log_netdev_debug(netdev, "OVS port queued for reconciliation");
        return 0;
}

static int ovs_reconcile_tunnel(Manager *m, NetDev *netdev, sd_json_variant **ops) {
        OVSTunnel *t;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *external_ids = NULL, *options = NULL,
                *iface_row = NULL, *iface_op = NULL, *iface_ref = NULL, *port_row = NULL, *port_op = NULL,
                *port_ref = NULL, *where = NULL, *mutations = NULL, *mutate_op = NULL;
        _cleanup_free_ char *iface_uuid_name = NULL, *port_uuid_name = NULL, *remote_str = NULL,
                *local_str = NULL, *key_str = NULL;
        int r;

        assert(netdev);
        assert(ops);

        t = OVS_TUNNEL(netdev);

        /* Check if tunnel port already exists in monitor cache */
        OVSDBMonitor *mon = ovsdb_client_get_monitor(m->ovsdb);
        bool tunnel_exists = false, have_tunnel_port_uuid = false;
        sd_id128_t tunnel_port_uuid = SD_ID128_NULL;
        if (mon) {
                struct ovs_name_check check = ovs_lookup_by_name(mon, "Port", netdev->ifname);
                tunnel_exists = check.found;
                if (check.found) {
                        tunnel_port_uuid = check.uuid;
                        have_tunnel_port_uuid = true;
                }
        }

        iface_uuid_name = ovs_make_uuid_name("iface_", netdev->ifname);
        if (!iface_uuid_name)
                return log_oom();

        port_uuid_name = ovs_make_uuid_name("port_", netdev->ifname);
        if (!port_uuid_name)
                return log_oom();

        r = ovs_build_external_ids(netdev->filename, &external_ids);
        if (r < 0)
                return log_netdev_warning_errno(netdev, r, "Failed to build external_ids: %m");

        /* Build tunnel options map */
        r = in_addr_to_string(t->remote_family, &t->remote, &remote_str);
        if (r < 0)
                return log_netdev_warning_errno(netdev, r, "Failed to format remote address: %m");

        if (t->local_family != AF_UNSPEC) {
                r = in_addr_to_string(t->local_family, &t->local, &local_str);
                if (r < 0)
                        return log_netdev_warning_errno(netdev, r, "Failed to format local address: %m");
        }

        if (t->key_set) {
                r = asprintf(&key_str, "%" PRIu32, t->key);
                if (r < 0)
                        return log_oom();
        }

        /* Options map: ["map", [["remote_ip","x.x.x.x"], ...]] */
        {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *opts_inner = NULL;

                /* Always have remote_ip */
                r = sd_json_variant_append_arrayb(
                                &opts_inner,
                                SD_JSON_BUILD_ARRAY(
                                        JSON_BUILD_CONST_STRING("remote_ip"),
                                        SD_JSON_BUILD_STRING(remote_str)));
                if (r < 0)
                        return r;

                if (local_str) {
                        r = sd_json_variant_append_arrayb(
                                        &opts_inner,
                                        SD_JSON_BUILD_ARRAY(
                                                JSON_BUILD_CONST_STRING("local_ip"),
                                                SD_JSON_BUILD_STRING(local_str)));
                        if (r < 0)
                                return r;
                }

                if (key_str) {
                        r = sd_json_variant_append_arrayb(
                                        &opts_inner,
                                        SD_JSON_BUILD_ARRAY(
                                                JSON_BUILD_CONST_STRING("key"),
                                                SD_JSON_BUILD_STRING(key_str)));
                        if (r < 0)
                                return r;
                }

                if (t->destination_port > 0) {
                        _cleanup_free_ char *port_str = NULL;
                        r = asprintf(&port_str, "%" PRIu16, t->destination_port);
                        if (r < 0)
                                return log_oom();

                        r = sd_json_variant_append_arrayb(
                                        &opts_inner,
                                        SD_JSON_BUILD_ARRAY(
                                                JSON_BUILD_CONST_STRING("dst_port"),
                                                SD_JSON_BUILD_STRING(port_str)));
                        if (r < 0)
                                return r;
                }

                /* TOS=0 and unset both mean "inherit" in OVS, so we only send tos when > 0 */
                if (t->tos > 0) {
                        _cleanup_free_ char *tos_str = NULL;
                        r = asprintf(&tos_str, "%" PRIu8, t->tos);
                        if (r < 0)
                                return log_oom();

                        r = sd_json_variant_append_arrayb(
                                        &opts_inner,
                                        SD_JSON_BUILD_ARRAY(
                                                JSON_BUILD_CONST_STRING("tos"),
                                                SD_JSON_BUILD_STRING(tos_str)));
                        if (r < 0)
                                return r;
                }

                if (t->ttl > 0) {
                        _cleanup_free_ char *ttl_str = NULL;
                        r = asprintf(&ttl_str, "%" PRIu8, t->ttl);
                        if (r < 0)
                                return log_oom();

                        r = sd_json_variant_append_arrayb(
                                        &opts_inner,
                                        SD_JSON_BUILD_ARRAY(
                                                JSON_BUILD_CONST_STRING("ttl"),
                                                SD_JSON_BUILD_STRING(ttl_str)));
                        if (r < 0)
                                return r;
                }

                if (t->dont_fragment >= 0) {
                        r = sd_json_variant_append_arrayb(
                                        &opts_inner,
                                        SD_JSON_BUILD_ARRAY(
                                                JSON_BUILD_CONST_STRING("df_default"),
                                                SD_JSON_BUILD_STRING(t->dont_fragment > 0 ? "true" : "false")));
                        if (r < 0)
                                return r;
                }

                r = sd_json_build(
                                &options,
                                SD_JSON_BUILD_ARRAY(
                                        JSON_BUILD_CONST_STRING("map"),
                                        SD_JSON_BUILD_VARIANT(opts_inner)));
                if (r < 0)
                        return r;
        }

        if (tunnel_exists) {
                /* UPDATE existing Interface options and external_ids */
                struct ovs_name_check iface_check = ovs_lookup_by_name(mon, "Interface", netdev->ifname);

                log_netdev_debug(netdev, "OVS tunnel '%s' already exists, updating", strna(netdev->ifname));

                if (iface_check.found) {
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *update_iface = NULL,
                                *update_where = NULL, *update_op = NULL;

                        /* Also update Interface.type so Type= changes (e.g. vxlan → gre)
                         * take effect on reload/reconnect, not just options changes. */
                        r = sd_json_buildo(
                                        &update_iface,
                                        SD_JSON_BUILD_PAIR_STRING("type", t->type),
                                        SD_JSON_BUILD_PAIR_VARIANT("options", options),
                                        SD_JSON_BUILD_PAIR_VARIANT("external_ids", external_ids));
                        if (r < 0)
                                return r;

                        r = ovsdb_where_uuid(iface_check.uuid, &update_where);
                        if (r < 0)
                                return r;

                        r = ovsdb_op_update("Interface", update_where, update_iface, &update_op);
                        if (r < 0)
                                return r;

                        r = sd_json_variant_append_array(ops, update_op);
                        if (r < 0)
                                return r;
                } else
                        /* Port row exists but Interface row not yet in cache (split delivery
                         * across monitor_cond updates). Skip just the Interface UPDATE — the
                         * next monitor update fires another reconcile that picks it up. We
                         * still continue to refresh Port external_ids and bridge membership
                         * below, so Bridge=/.netdev rename changes aren't dropped. */
                        log_netdev_debug(netdev, "OVS tunnel '%s' Port found but Interface row missing in cache, deferring Interface update",
                                         strna(netdev->ifname));

                if (have_tunnel_port_uuid) {
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *port_update_row = NULL,
                                *port_update_where = NULL, *port_update_op = NULL;

                        /* Refresh Port.external_ids so a .netdev rename / SourcePath change
                         * surfaces in OVSDB without waiting for a manual ovs-vsctl. The Port
                         * row itself is otherwise immutable from networkd's view (no Tag/VLAN/
                         * bond columns on a tunnel Port). */
                        r = sd_json_buildo(
                                        &port_update_row,
                                        SD_JSON_BUILD_PAIR_VARIANT("external_ids", external_ids));
                        if (r < 0)
                                return r;

                        r = ovsdb_where_uuid(tunnel_port_uuid, &port_update_where);
                        if (r < 0)
                                return r;

                        r = ovsdb_op_update("Port", port_update_where, port_update_row, &port_update_op);
                        if (r < 0)
                                return r;

                        r = sd_json_variant_append_array(ops, port_update_op);
                        if (r < 0)
                                return r;

                        /* If the parent bridge changed, move the tunnel Port between bridges */
                        r = ovs_ensure_port_bridge_membership(m, tunnel_port_uuid, t->bridge, ops);
                        if (r < 0)
                                return r;
                }

                /* READY transition deferred to ovs_reconcile_done on ACK */
                return 0;
        }

        /* 1. Insert Interface with tunnel type and options */
        r = sd_json_buildo(
                        &iface_row,
                        SD_JSON_BUILD_PAIR_STRING("name", netdev->ifname),
                        SD_JSON_BUILD_PAIR_STRING("type", t->type),
                        SD_JSON_BUILD_PAIR_VARIANT("options", options),
                        SD_JSON_BUILD_PAIR_VARIANT("external_ids", external_ids));
        if (r < 0)
                return log_netdev_warning_errno(netdev, r, "Failed to build Interface row: %m");

        r = ovsdb_op_insert("Interface", iface_uuid_name, iface_row, &iface_op);
        if (r < 0)
                return r;

        r = sd_json_variant_append_array(ops, iface_op);
        if (r < 0)
                return r;

        /* 2. Insert Port */
        r = ovs_build_named_uuid_ref(iface_uuid_name, &iface_ref);
        if (r < 0)
                return r;

        r = sd_json_buildo(
                        &port_row,
                        SD_JSON_BUILD_PAIR_STRING("name", netdev->ifname),
                        SD_JSON_BUILD_PAIR_VARIANT("interfaces", iface_ref),
                        SD_JSON_BUILD_PAIR_VARIANT("external_ids", external_ids));
        if (r < 0)
                return log_netdev_warning_errno(netdev, r, "Failed to build Port row: %m");

        r = ovsdb_op_insert("Port", port_uuid_name, port_row, &port_op);
        if (r < 0)
                return r;

        r = sd_json_variant_append_array(ops, port_op);
        if (r < 0)
                return r;

        /* 3. Mutate parent bridge: ports += ["named-uuid", "port-<name>"] */
        r = ovs_build_named_uuid_ref(port_uuid_name, &port_ref);
        if (r < 0)
                return r;

        r = sd_json_build(
                        &where,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_ARRAY(
                                        JSON_BUILD_CONST_STRING("name"),
                                        JSON_BUILD_CONST_STRING("=="),
                                        SD_JSON_BUILD_STRING(t->bridge))));
        if (r < 0)
                return r;

        r = sd_json_build(
                        &mutations,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_ARRAY(
                                        JSON_BUILD_CONST_STRING("ports"),
                                        JSON_BUILD_CONST_STRING("insert"),
                                        SD_JSON_BUILD_ARRAY(
                                                JSON_BUILD_CONST_STRING("set"),
                                                SD_JSON_BUILD_ARRAY(
                                                        SD_JSON_BUILD_VARIANT(port_ref))))));
        if (r < 0)
                return r;

        r = ovsdb_op_mutate("Bridge", where, mutations, &mutate_op);
        if (r < 0)
                return r;

        r = sd_json_variant_append_array(ops, mutate_op);
        if (r < 0)
                return r;

        log_netdev_debug(netdev, "OVS tunnel queued for reconciliation");
        return 0;
}

static int ovs_reconcile_network_port_one(Manager *m, Network *network, const char *ifname, sd_json_variant **ops) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *external_ids = NULL, *iface_row = NULL,
                *iface_op = NULL, *iface_ref = NULL, *port_row = NULL, *port_op = NULL, *port_ref = NULL,
                *where = NULL, *mutations = NULL, *mutate_op = NULL;
        _cleanup_free_ char *iface_uuid_name = NULL, *port_uuid_name = NULL;
        int r;

        assert(m);
        assert(network);
        assert(ifname);
        assert(ops);

        /* If a .netdev of kind OVS_PORT or OVS_TUNNEL already manages this interface,
         * skip .network attachment to avoid named-uuid collisions in the transact. */
        {
                NetDev *existing;
                if (netdev_get(m, ifname, &existing) >= 0 &&
                    IN_SET(existing->kind, NETDEV_KIND_OVS_PORT, NETDEV_KIND_OVS_TUNNEL)) {
                        log_debug("Interface '%s' already managed as OVS port/tunnel netdev, skipping .network attachment",
                                  ifname);
                        return 0;
                }
        }

        /* Check that the target bridge exists before attaching */
        OVSDBMonitor *mon = ovsdb_client_get_monitor(m->ovsdb);
        if (mon) {
                struct ovs_name_check check = ovs_lookup_by_name(mon, "Bridge", network->ovs_bridge_name);
                if (!check.found) {
                        /* Check if bridge is being created in this same reconcile cycle */
                        NetDev *bridge_nd;
                        if (netdev_get(m, network->ovs_bridge_name, &bridge_nd) < 0 ||
                            bridge_nd->kind != NETDEV_KIND_OVS_BRIDGE) {
                                log_debug("OVS bridge '%s' not found in OVSDB or config, deferring port attachment for '%s'",
                                          network->ovs_bridge_name, ifname);
                                return 0;
                        }
                        log_debug("OVS bridge '%s' being created in same transact, proceeding with attachment for '%s'",
                                  network->ovs_bridge_name, ifname);
                }
        }

        /* If port already exists in monitor cache, UPDATE instead of INSERT */
        if (mon) {
                struct ovs_name_check check = ovs_lookup_by_name(mon, "Port", ifname);
                if (check.found) {
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *update_row = NULL,
                                *update_where = NULL, *update_op = NULL, *update_ext = NULL;

                        log_debug("OVS port '%s' (from .network) already exists, updating", ifname);

                        r = ovs_build_external_ids(network->filename, &update_ext);
                        if (r < 0)
                                return r;

                        /* Always emit optional columns so removed config resets the OVSDB column */
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *tag_v = NULL, *vlan_mode_v = NULL;

                        r = ovs_build_optional_int(network->ovs_port_tag, network->ovs_port_tag != VLANID_INVALID, &tag_v);
                        if (r < 0)
                                return r;
                        r = ovs_build_optional_string(ovs_port_vlan_mode_to_string(network->ovs_port_vlan_mode), &vlan_mode_v);
                        if (r < 0)
                                return r;

                        r = sd_json_buildo(
                                        &update_row,
                                        SD_JSON_BUILD_PAIR_VARIANT("tag", tag_v),
                                        SD_JSON_BUILD_PAIR_VARIANT("vlan_mode", vlan_mode_v),
                                        SD_JSON_BUILD_PAIR_VARIANT("external_ids", update_ext));
                        if (r < 0)
                                return r;

                        r = ovsdb_where_uuid(check.uuid, &update_where);
                        if (r < 0)
                                return r;

                        r = ovsdb_op_update("Port", update_where, update_row, &update_op);
                        if (r < 0)
                                return r;

                        r = sd_json_variant_append_array(ops, update_op);
                        if (r < 0)
                                return r;

                        /* If the .network's OVSBridge= changed, move the Port between bridges */
                        r = ovs_ensure_port_bridge_membership(m, check.uuid, network->ovs_bridge_name, ops);
                        if (r < 0)
                                return r;

                        return 0;
                }
        }

        iface_uuid_name = ovs_make_uuid_name("iface_", ifname);
        if (!iface_uuid_name)
                return log_oom();

        port_uuid_name = ovs_make_uuid_name("port_", ifname);
        if (!port_uuid_name)
                return log_oom();

        r = ovs_build_external_ids(network->filename, &external_ids);
        if (r < 0)
                return log_warning_errno(r, "Failed to build external_ids for '%s': %m", network->filename);

        /* 1. Insert Interface (system port: type="") */
        r = sd_json_buildo(
                        &iface_row,
                        SD_JSON_BUILD_PAIR_STRING("name", ifname),
                        SD_JSON_BUILD_PAIR_STRING("type", ""),
                        SD_JSON_BUILD_PAIR_VARIANT("external_ids", external_ids));
        if (r < 0)
                return log_warning_errno(r, "Failed to build Interface row for '%s': %m", ifname);

        r = ovsdb_op_insert("Interface", iface_uuid_name, iface_row, &iface_op);
        if (r < 0)
                return r;

        r = sd_json_variant_append_array(ops, iface_op);
        if (r < 0)
                return r;

        /* 2. Insert Port */
        r = ovs_build_named_uuid_ref(iface_uuid_name, &iface_ref);
        if (r < 0)
                return r;

        r = sd_json_buildo(
                        &port_row,
                        SD_JSON_BUILD_PAIR_STRING("name", ifname),
                        SD_JSON_BUILD_PAIR_VARIANT("interfaces", iface_ref),
                        SD_JSON_BUILD_PAIR_CONDITION(network->ovs_port_tag != VLANID_INVALID, "tag", SD_JSON_BUILD_INTEGER(network->ovs_port_tag)),
                        SD_JSON_BUILD_PAIR_CONDITION(network->ovs_port_vlan_mode >= 0, "vlan_mode", SD_JSON_BUILD_STRING(ovs_port_vlan_mode_to_string(network->ovs_port_vlan_mode))),
                        SD_JSON_BUILD_PAIR_VARIANT("external_ids", external_ids));
        if (r < 0)
                return log_warning_errno(r, "Failed to build Port row for '%s': %m", ifname);

        r = ovsdb_op_insert("Port", port_uuid_name, port_row, &port_op);
        if (r < 0)
                return r;

        r = sd_json_variant_append_array(ops, port_op);
        if (r < 0)
                return r;

        /* 3. Mutate parent bridge: ports += ["named-uuid", "port_<name>"] */
        r = ovs_build_named_uuid_ref(port_uuid_name, &port_ref);
        if (r < 0)
                return r;

        r = sd_json_build(
                        &where,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_ARRAY(
                                        JSON_BUILD_CONST_STRING("name"),
                                        JSON_BUILD_CONST_STRING("=="),
                                        SD_JSON_BUILD_STRING(network->ovs_bridge_name))));
        if (r < 0)
                return r;

        r = sd_json_build(
                        &mutations,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_ARRAY(
                                        JSON_BUILD_CONST_STRING("ports"),
                                        JSON_BUILD_CONST_STRING("insert"),
                                        SD_JSON_BUILD_ARRAY(
                                                JSON_BUILD_CONST_STRING("set"),
                                                SD_JSON_BUILD_ARRAY(
                                                        SD_JSON_BUILD_VARIANT(port_ref))))));
        if (r < 0)
                return r;

        r = ovsdb_op_mutate("Bridge", where, mutations, &mutate_op);
        if (r < 0)
                return r;

        r = sd_json_variant_append_array(ops, mutate_op);
        if (r < 0)
                return r;

        log_debug("OVS .network port '%s' -> bridge '%s' queued for reconciliation", ifname, network->ovs_bridge_name);
        return 0;
}

static int ovs_reconcile_network_port(Manager *m, Network *network, sd_json_variant **ops) {
        Link *link;
        int r;

        assert(m);
        assert(network);
        assert(ops);

        /* Iterate Links whose effective .network is this one. This respects networkd's
         * matcher (including globs in Match.Name=, MACAddress=, Driver=, etc.) — we use
         * the concrete ifname of each matched Link as the attached OVS port name. */
        HASHMAP_FOREACH(link, m->links_by_index) {
                if (link->network != network)
                        continue;
                if (!link->ifname)
                        continue;

                r = ovs_reconcile_network_port_one(m, network, link->ifname, ops);
                if (r == -ENOMEM)
                        return r;
                if (r < 0)
                        log_warning_errno(r, "Failed to attach '%s' to OVS bridge: %m", link->ifname);
        }

        return 0;
}

static int manager_ovs_client_drop_handler(sd_event_source *s, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        m->ovs_client_drop_defer = sd_event_source_disable_unref(m->ovs_client_drop_defer);
        m->ovs_dying = ovsdb_client_unref(m->ovs_dying);
        return 0;
}

/* Schedule m->ovsdb for unref outside the current call stack, NULLing it immediately so all
 * callers (and the cancel_all callbacks that fire when it is finally freed) observe NULL right
 * away. This is frequently reached from inside the client's own dispatch — the FAILED state
 * callback, or a transact/monitor reply — where ovsdb_client_unref() would free the client and
 * the JsonStream embedded in it while json_stream_io_callback() is still on the stack and about
 * to touch that stream. Deferring the unref guarantees the dispatch stack has unwound first. */
static void manager_ovs_drop_client(Manager *m) {
        int r;

        assert(m);

        if (!m->ovsdb)
                return;

        /* Detach any prior still-dying client into a local *before* touching the slot, then
         * stash the current client and NULL m->ovsdb. The prior is unref'd only at the very
         * end, by which point m->ovsdb is NULL and m->ovs_dying already holds the current
         * client: if the prior's cancel_all callbacks re-enter manager_ovs_drop_client() they
         * see no live client and no-op, and cannot clobber the freshly-stashed slot. We never
         * unref the *current* client synchronously here, so a drop from inside that client's
         * own dispatch can't free the JsonStream out from under json_stream_io_callback(). */
        OVSDBClient *prior = TAKE_PTR(m->ovs_dying);
        m->ovs_dying = TAKE_PTR(m->ovsdb);

        /* Sever the dying client's callbacks before it lingers in m->ovs_dying: until the deferred
         * handler unref's it (or, if the defer-arm below fails on OOM, the next drop / manager_free
         * does), it stays attached to the event loop. A late state/notify/update event must not
         * re-enter the Manager and act on the now-replaced m->ovsdb. */
        ovsdb_client_bind_state_change(m->ovs_dying, NULL);
        ovsdb_client_bind_notify(m->ovs_dying, NULL);
        ovsdb_client_bind_update(m->ovs_dying, NULL);
        ovsdb_client_set_userdata(m->ovs_dying, NULL);

        if (!m->ovs_client_drop_defer) {
                r = sd_event_add_defer(m->event, &m->ovs_client_drop_defer, manager_ovs_client_drop_handler, m);
                if (r < 0)
                        /* Cannot defer (OOM): leave the current client stashed in m->ovs_dying for
                         * the next drop or manager_free() to release. Leaking one client until then
                         * is preferable to a synchronous unref from inside dispatch (use-after-free). */
                        log_warning_errno(r, "Failed to defer OVSDB client unref, will retry on next drop: %m");
        }

        /* Safe: prior was dropped in an earlier iteration, so we are not inside its dispatch. */
        ovsdb_client_unref(prior);
}

/* Drain a deferred teardown that has been waiting on in-flight transacts. Returns true
 * if the client was dropped (caller may want to skip further work on m->ovsdb). Safe to
 * call unconditionally — it no-ops unless all the preconditions are met. */
static bool ovs_drain_pending_teardown(Manager *m, const char *log_msg) {
        assert(m);
        assert(log_msg);

        if (!(m->ovsdb && m->ovs_pending_teardown && m->ovs_inflight_transacts == 0))
                return false;

        log_debug("%s", log_msg);
        m->ovs_pending_teardown = false;
        m->ovs_reconnect_timer = sd_event_source_disable_unref(m->ovs_reconnect_timer);
        m->ovs_reconnect_delay = 0;
        m->ovs_reconcile_pending = false;
        manager_ovs_drop_client(m);           /* deferred — may run inside client dispatch */
        return true;
}

static int ovs_reconcile_done(
                OVSDBClient *client,
                sd_json_variant *result,
                sd_json_variant *error,
                void *userdata) {

        Manager *m = ASSERT_PTR(userdata);
        int r;

        if (m->ovs_inflight_transacts > 0)
                m->ovs_inflight_transacts--;

        /* Aborted transact: server never applied the ops. Two paths produce
         * result==NULL: ovsdb_client_unref cancel (NULL/NULL via cancel_all),
         * and runtime FAILED-state cancel (NULL plus synthetic_error="connection
         * failed", emitted from ovsdb_client_set_state). Treat both identically
         * — silent log_debug, no warnings, no post-processing. The next
         * reconcile after reconnect will rebuild whatever state was lost.
         * The minimal guard was added in the reconciler commit; here we extend
         * it to also drain coalesced reconciles via try_pending. */
        if (!result) {
                log_debug("OVS reconcile transact aborted (cancel/disconnect), skipping post-processing");
                goto try_pending;
        }

        if (error) {
                _cleanup_free_ char *text = NULL;
                (void) sd_json_variant_format(error, 0, &text);
                log_warning("OVS reconciliation failed: %s", strna(text));
                goto try_pending;
        }

        /* Check per-op results -- result is an array of per-op results.
         * NULL result is already handled above, so just guard against unexpected
         * non-array shapes. */
        if (sd_json_variant_is_array(result)) {
                bool had_errors = false;
                size_t n_ops = sd_json_variant_elements(result);
                log_debug("OVS reconciliation completed: %zu operations", n_ops);

                for (size_t i = 0; i < n_ops; i++) {
                        sd_json_variant *op_result = sd_json_variant_by_index(result, i);
                        sd_json_variant *err;

                        /* Comment ops return empty objects; abort/malformed replies may be non-objects */
                        if (!op_result || !sd_json_variant_is_object(op_result))
                                continue;

                        err = sd_json_variant_by_key(op_result, "error");
                        if (err && !sd_json_variant_is_null(err)) {
                                _cleanup_free_ char *text = NULL;
                                (void) sd_json_variant_format(op_result, 0, &text);
                                log_warning("OVS transact op error: %s", strna(text));
                                had_errors = true;
                        }
                }

                /* OVSDB transactions are atomic: if any op fails, all ops are rolled back.
                 * Only transition netdevs to READY when the entire transaction succeeded. */
                if (!had_errors) {
                        NetDev *netdev;
                        HASHMAP_FOREACH(netdev, m->netdevs) {
                                if (netdev->state != NETDEV_STATE_CREATING)
                                        continue;

                                /* Kernel-backed kinds normally transition to READY via
                                 * RTM_NEWLINK in their set_ifindex callbacks. But after a
                                 * daemon-reload that replaced the NetDev object while the
                                 * kernel interface already existed, no new RTM_NEWLINK will
                                 * fire. Mark them READY here if they already have an ifindex
                                 * bound from prior enumeration. */
                                switch (netdev->kind) {
                                case NETDEV_KIND_OVS_BRIDGE:
                                        if (netdev->ifindex <= 0)
                                                continue;  /* wait for RTM_NEWLINK */
                                        break;

                                case NETDEV_KIND_OVS_PORT: {
                                        OVSPort *p = OVS_PORT(netdev);
                                        if (p->type == OVS_PORT_TYPE_INTERNAL && netdev->ifindex <= 0)
                                                continue;  /* internal port waits for RTM_NEWLINK */
                                        /* A bond Port without member interfaces is rejected by
                                         * OVSDB (Port.interfaces min=1), and ovs_reconcile_port
                                         * skips emitting any ops for it. Marking it READY here
                                         * would falsely claim success — leave in CREATING so the
                                         * next reconcile (after a member shows up) can complete it. */
                                        if (p->type == OVS_PORT_TYPE_BOND) {
                                                OVSDBMonitor *mon = ovsdb_client_get_monitor(m->ovsdb);
                                                struct ovs_name_check check = ovs_lookup_by_name(mon, "Port", netdev->ifname);
                                                if (!check.found)
                                                        continue;
                                        }
                                        /* Patch/bond-with-members and already-bound internal ports: OK */
                                        break;
                                }

                                case NETDEV_KIND_OVS_TUNNEL:
                                        /* Tunnel kernel netdev (if any) has a different name,
                                         * so we can't match it by ifname. Go READY on OVSDB
                                         * confirmation. */
                                        break;

                                default:
                                        /* Not an OVS kind */
                                        continue;
                                }

                                (void) netdev_enter_ready(netdev);
                        }
                }
        } else
                log_warning("OVS reconciliation: unexpected response (connection dropped?)");

try_pending:
        /* Drain any reconcile that was coalesced while this transact was in
         * flight (per-link hooks, reload arriving mid-transact). Bound the
         * recursion: do nothing if there's still an in-flight transact (some
         * other reply will pick it up) or if the new reconcile coalesces too.
         *
         * Skip when m->ovsdb is NULL or the client is not READY: this happens
         * when ovsdb_client_unref() drains in-flight callbacks during runtime
         * teardown / reconnect. ovs_reconcile() would otherwise log a confusing
         * "OVSDB client not available" warning for what is a normal disconnect,
         * and the next reconnect's snapshot reconcile will re-pick up the
         * deferred work anyway. */
        if (m->ovsdb &&
            ovsdb_client_get_state(m->ovsdb) == OVSDB_CLIENT_READY &&
            m->ovs_reconcile_pending && m->ovs_inflight_transacts == 0) {
                m->ovs_reconcile_pending = false;
                log_debug("OVS reconcile: running coalesced pending reconcile");
                r = ovs_reconcile(m);
                if (r < 0) {
                        /* Restore pending so the deferred work isn't lost — a future
                         * monitor update or manager_ovs_maybe_start (reload) will retry. */
                        m->ovs_reconcile_pending = true;
                        log_warning_errno(r, "OVS coalesced reconcile failed, will retry: %m");
                }
        }

        /* Deferred teardown after the last OVS config was removed: now that the
         * delete-only reconcile transact has been acknowledged, drop the client
         * and clear lifecycle state. Skip if a coalesced pending reconcile re-armed
         * inflight above; that next reply will revisit the teardown. */
        (void) ovs_drain_pending_teardown(m, "OVS pending teardown: drained, releasing client");

        return 0;
}

static int ovs_clear_done(
                OVSDBClient *client,
                sd_json_variant *result,
                sd_json_variant *error,
                void *userdata) {

        Manager *m = ASSERT_PTR(userdata);
        int r;

        if (m->ovs_inflight_transacts > 0)
                m->ovs_inflight_transacts--;

        /* Aborted transact (cancel from unref, or runtime FAILED-state). Skip
         * the post-clear bookkeeping: the database state is unknown, and the
         * next reconnect will re-attempt the clear via the marker file.
         * result==NULL covers both NULL/NULL (unref cancel) and NULL with
         * synthetic_error="connection failed" (FAILED-state cancel).
         *
         * Mirror the teardown-drain logic from ovs_reconcile_done: if the abort
         * drained the last in-flight transact and a teardown was pending, run it
         * now — otherwise nobody re-checks the flag. */
        /* All exit paths below route through `finish:`, which drains a pending teardown once the
         * last in-flight transact completes. Keeping that the single chokepoint (rather than an
         * opt-in call bolted onto each path) means a new return path cannot silently strand the
         * teardown with a live client. */

        if (!result) {
                log_debug("OVS clear transact aborted (cancel/disconnect), skipping post-processing");
                goto finish;
        }

        if (error) {
                _cleanup_free_ char *text = NULL;
                (void) sd_json_variant_format(error, 0, &text);
                log_warning("OVS database clear failed: %s, running reconcile anyway", strna(text));
                /* Don't set the marker on error — next reconnect may retry the clear.
                 * Still run reconcile so desired state is applied on top of existing DB. */
                r = ovs_reconcile(m);
                if (r < 0)
                        log_warning_errno(r, "OVS reconciliation after failed clear: %m");
                goto finish;
        }

        /* Validate per-op results: each op should be an object without an "error" key.
         * Don't mark the clear as successful if any op failed. */
        if (!sd_json_variant_is_array(result)) {
                log_warning("OVS clear returned unexpected (non-array) result, not setting marker");
                goto finish;
        }

        for (size_t i = 0; i < sd_json_variant_elements(result); i++) {
                sd_json_variant *op_result = sd_json_variant_by_index(result, i);
                sd_json_variant *err;

                if (!op_result || !sd_json_variant_is_object(op_result))
                        continue;

                err = sd_json_variant_by_key(op_result, "error");
                if (err && !sd_json_variant_is_null(err)) {
                        _cleanup_free_ char *text = NULL;
                        (void) sd_json_variant_format(op_result, 0, &text);
                        log_warning("OVS clear op error: %s, not setting marker", strna(text));
                        /* Still run reconcile so desired state is applied */
                        r = ovs_reconcile(m);
                        if (r < 0)
                                log_warning_errno(r, "OVS reconciliation after partial clear: %m");
                        goto finish;
                }
        }

        /* Set marker only on confirmed success so next reconnect-within-same-boot skips the clear.
         * Use /run/systemd/netif/ — that's networkd's RuntimeDirectory= and is the only
         * /run subtree systemd-network has write access to. */
        r = touch_file("/run/systemd/netif/ovs-cleared",
                       /* parents= */ true, USEC_INFINITY,
                       UID_INVALID, GID_INVALID, MODE_INVALID);
        if (r < 0)
                log_warning_errno(r, "Failed to create OVS clear marker file, continuing anyway: %m");

        log_info("OVS database cleared successfully");

        /* The post-clear monitor update2 typically arrives BEFORE the transact
         * reply (server broadcasts the row deletions to all subscribers, then
         * sends our reply). In that ordering manager_ovs_on_update has already
         * fired with inflight>0 and was either suppressed (the prior code path)
         * or set ovs_reconcile_pending (current path). Either way, we just
         * decremented inflight to 0 and the deletions are in the cache —
         * either run reconcile inline (cache reflects empty DB) or arm the
         * unified pending flag (cache still pre-clear; the in-flight update2
         * for the deletes will arrive next and on_update will pick up the
         * pending flag). */
        /* OVSDB garbage-collects orphaned Port/Interface rows after Bridge=>{} via
         * the strong-reference chain, but those delete update2's may not have arrived
         * yet when we get here. Wait until ALL three tables are empty in our cache so
         * inline reconcile doesn't see stale Port rows for already-deleted bridges. */
        OVSDBMonitor *mon = ovsdb_client_get_monitor(client);
        if (mon && ovsdb_monitor_count(mon, "Bridge") == 0 &&
            ovsdb_monitor_count(mon, "Port") == 0 &&
            ovsdb_monitor_count(mon, "Interface") == 0) {
                log_debug("OVS post-clear cache already empty, running reconcile inline");
                /* Consume any pending flag the suppressed update2 may have
                 * set: we are about to run reconcile right now, so the
                 * reconcile_done try_pending path must not trigger a second
                 * one. */
                m->ovs_reconcile_pending = false;
                r = ovs_reconcile(m);
                if (r < 0)
                        log_warning_errno(r, "OVS reconciliation after clear failed: %m");
        } else {
                log_debug("OVS post-clear cache not yet drained, deferring reconcile via pending flag");
                m->ovs_reconcile_pending = true;
        }

finish:
        /* Single teardown-drain chokepoint: if this was the last in-flight transact and a
         * teardown is pending, drop the client. A no-op when no teardown is pending or another
         * transact is still in flight (its reply will revisit this). */
        (void) ovs_drain_pending_teardown(m, "OVS clear: draining pending teardown after transact completion");
        return 0;
}

int ovs_clear_database(Manager *m) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *ops = NULL, *where_all = NULL, *update_row = NULL,
                *update_op = NULL, *comment_op = NULL, *empty_set = NULL;
        int r;

        assert(m);
        assert(m->ovsdb);

        r = ovsdb_where_all(&where_all);
        if (r < 0)
                return r;

        /* Set bridges to empty set. OVSDB garbage-collects orphaned
         * Bridge/Port/Interface rows via strong-reference chain. */
        r = sd_json_build(&empty_set,
                        SD_JSON_BUILD_ARRAY(
                                JSON_BUILD_CONST_STRING("set"),
                                SD_JSON_BUILD_EMPTY_ARRAY));
        if (r < 0)
                return r;

        /* Only clear bridges — networkd manages bridges, not OVSDB manager_options
         * or SSL settings (those may be provisioned out-of-band by OpenStack/OVN). */
        r = sd_json_buildo(
                        &update_row,
                        SD_JSON_BUILD_PAIR_VARIANT("bridges", empty_set));
        if (r < 0)
                return r;

        r = ovsdb_op_update("Open_vSwitch", where_all, update_row, &update_op);
        if (r < 0)
                return r;

        r = sd_json_variant_append_array(&ops, update_op);
        if (r < 0)
                return r;

        r = ovsdb_op_comment("systemd-networkd: ClearDatabaseOnBoot", &comment_op);
        if (r < 0)
                return r;

        r = sd_json_variant_append_array(&ops, comment_op);
        if (r < 0)
                return r;

        log_info("Clearing OVS database (ClearDatabaseOnBoot=yes)");

        m->ovs_inflight_transacts++;
        r = ovsdb_client_transact(m->ovsdb, ops, ovs_clear_done, m);
        if (r < 0) {
                m->ovs_inflight_transacts--;
                return log_warning_errno(r, "Failed to send OVS clear transact: %m");
        }

        return 0;
}

int ovs_reconcile(Manager *m) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *ops = NULL, *comment_op = NULL;
        NetDev *netdev;
        Network *network;
        int r;

        assert(m);

        if (!m->ovsdb) {
                log_warning("OVS reconciliation requested but OVSDB client not available");
                return -ENOTCONN;
        }

        /* Don't reconcile until the OVSDB monitor snapshot has arrived.
         *
         * Otherwise the existence checks in ovs_reconcile_{bridge,port,tunnel} see an
         * empty cache, take the INSERT path, and OVSDB rejects the transact with a
         * "constraint violation" because the row already exists in the database
         * (typical at networkd restart, when ovs-vswitchd has kept the rows from the
         * previous session).
         *
         * Return success silently rather than an error: every caller of
         * ovs_reconcile() either runs at startup (link_reconfigure_full hook), at
         * reload (manager_ovs_maybe_start), or after a OVSDB transact reply
         * (ovs_clear_done). The first reconcile that actually has authoritative
         * state is dispatched from manager_ovs_on_monitor_initial() once the
         * snapshot lands; nobody else needs to retry. Treating this as 0 keeps
         * call sites trivial and avoids leaking a confusing "Resource temporarily
         * unavailable" warning to operators. */
        if (!ovsdb_client_get_monitor(m->ovsdb)) {
                log_debug("OVS reconcile deferred: monitor snapshot not yet received");
                return 0;
        }

        /* Coalesce: if a transact is already in flight, the next *_done callback
         * picks up the pending flag and re-runs reconcile against the fresh
         * post-transact cache. Without this, a reload over N OVS-attached
         * links would issue N redundant full-DB transacts via the per-link
         * link_reconfigure_full hook (each transact is idempotent but each
         * still pays a wire-roundtrip and ops-build cost). */
        if (m->ovs_inflight_transacts > 0) {
                m->ovs_reconcile_pending = true;
                log_debug("OVS reconcile coalesced: %u transact(s) in flight, will re-run on drain",
                          m->ovs_inflight_transacts);
                return 0;
        }

        /* Phase 0: delete managed objects that are no longer in config */
        r = ovs_reconcile_delete(m, &ops);
        if (r < 0)
                return log_warning_errno(r, "Failed to build OVS delete ops: %m");

        /* Phase 1: bridges first (ports/tunnels reference them) */
        HASHMAP_FOREACH(netdev, m->netdevs) {
                if (netdev->kind != NETDEV_KIND_OVS_BRIDGE)
                        continue;

                r = ovs_reconcile_bridge(m, netdev, &ops);
                if (r < 0)
                        return log_warning_errno(r, "Failed to build OVS bridge ops for '%s': %m",
                                                 strna(netdev->ifname));
        }

        /* Phase 2: ports. Bond reconciliation needs the set of standalone Ports being deleted
         * this reconcile (so a member migrating from OVSBridge= to a bond does not reuse a
         * doomed Interface UUID). Compute it once here rather than rebuilding it per bond — but
         * only when a bond is actually configured, to avoid an extra Port-cache scan otherwise. */
        _cleanup_set_free_ Set *doomed_ports = NULL;
        bool have_bond = false;
        HASHMAP_FOREACH(netdev, m->netdevs)
                if (netdev->kind == NETDEV_KIND_OVS_PORT && OVS_PORT(netdev)->type == OVS_PORT_TYPE_BOND) {
                        have_bond = true;
                        break;
                }
        if (have_bond) {
                OVSDBMonitor *mon = ovsdb_client_get_monitor(m->ovsdb);
                if (mon) {
                        struct ovs_doomed_ports_ctx dctx = { .m = m };
                        ovsdb_monitor_foreach(mon, "Port", ovs_collect_doomed_ports_cb, &dctx);
                        /* Take ownership before the error check so the cleanup attribute frees the
                         * partially-built set on the dctx.error (OOM) path too. */
                        doomed_ports = TAKE_PTR(dctx.names);
                        if (dctx.error < 0)
                                return log_warning_errno(dctx.error, "Failed to collect OVS doomed ports: %m");
                }
        }

        HASHMAP_FOREACH(netdev, m->netdevs) {
                if (netdev->kind != NETDEV_KIND_OVS_PORT)
                        continue;

                r = ovs_reconcile_port(m, netdev, doomed_ports, &ops);
                if (r < 0)
                        return log_warning_errno(r, "Failed to build OVS port ops for '%s': %m",
                                                 strna(netdev->ifname));
        }

        /* Phase 3: tunnels */
        HASHMAP_FOREACH(netdev, m->netdevs) {
                if (netdev->kind != NETDEV_KIND_OVS_TUNNEL)
                        continue;

                r = ovs_reconcile_tunnel(m, netdev, &ops);
                if (r < 0)
                        return log_warning_errno(r, "Failed to build OVS tunnel ops for '%s': %m",
                                                 strna(netdev->ifname));
        }

        /* Phase 4: .network OVSBridge= attachments */
        ORDERED_HASHMAP_FOREACH(network, m->networks) {
                if (!network->ovs_bridge_name)
                        continue;

                r = ovs_reconcile_network_port(m, network, &ops);
                if (r < 0)
                        log_warning_errno(r, "Failed to build OVS attachment for '%s': %m", network->filename);
        }

        if (!ops) {
                log_debug("OVS reconciliation: no OVS netdevs configured, nothing to do");
                return 0;
        }

        /* Add a comment operation */
        r = ovsdb_op_comment("systemd-networkd reconciliation", &comment_op);
        if (r < 0)
                return r;

        r = sd_json_variant_append_array(&ops, comment_op);
        if (r < 0)
                return r;

        log_debug("OVS reconciliation: sending transact with %zu operations",
                  sd_json_variant_elements(ops));

        m->ovs_inflight_transacts++;
        r = ovsdb_client_transact(m->ovsdb, ops, ovs_reconcile_done, m);
        if (r < 0) {
                m->ovs_inflight_transacts--;
                return log_warning_errno(r, "Failed to send OVS reconciliation transact: %m");
        }

        return 0;
}

static void manager_count_ovs_usage(Manager *m) {
        NetDev *netdev;
        Network *network;

        assert(m);

        m->ovs_use_count = 0;

        HASHMAP_FOREACH(netdev, m->netdevs)
                if (IN_SET(netdev->kind,
                           NETDEV_KIND_OVS_BRIDGE,
                           NETDEV_KIND_OVS_PORT,
                           NETDEV_KIND_OVS_TUNNEL))
                        m->ovs_use_count++;

        ORDERED_HASHMAP_FOREACH(network, m->networks)
                if (network->ovs_bridge_name || network->ovs_bond_name)
                        m->ovs_use_count++;
}

#define OVS_DEFAULT_SOCKET_PATH "/run/openvswitch/db.sock"

static int manager_ovs_reconnect_handler(sd_event_source *s, uint64_t usec, void *userdata);

/* Drop the OVSDB client, clear lifecycle bookkeeping, and arm the reconnect timer
 * with exponential backoff (capped at 30s). Used by every error path that needs
 * to recover from a broken/unusable client. */
static void manager_ovs_schedule_reconnect(Manager *m) {
        int r;

        assert(m);

        m->ovs_inflight_transacts = 0;
        m->ovs_reconcile_pending = false;
        m->ovs_pending_teardown = false;
        manager_ovs_drop_client(m);       /* deferred — usually reached from inside client dispatch */

        if (m->ovs_reconnect_delay == 0)
                m->ovs_reconnect_delay = 1 * USEC_PER_SEC;
        m->ovs_reconnect_timer = sd_event_source_disable_unref(m->ovs_reconnect_timer);
        /* Add up to 500 ms jitter to avoid thundering-herd reconnects when many networkd
         * instances (e.g. containers sharing the host's ovsdb-server) all fail at once. */
        usec_t scheduled = m->ovs_reconnect_delay + random_u64_range(500 * USEC_PER_MSEC);
        r = sd_event_add_time_relative(m->event, &m->ovs_reconnect_timer,
                                       CLOCK_MONOTONIC, scheduled, 0,
                                       manager_ovs_reconnect_handler, m);
        if (r < 0) {
                log_warning_errno(r, "Failed to schedule OVS reconnect timer, OVS recovery disabled: %m");
                /* Don't inflate the backoff when the timer never armed: a future caller that
                 * succeeds in scheduling should start from the same delay we just attempted. */
                return;
        }

        log_info("OVSDB reconnect scheduled in %s",
                 FORMAT_TIMESPAN(scheduled, USEC_PER_SEC));
        m->ovs_reconnect_delay = MIN(m->ovs_reconnect_delay * 2, 30 * USEC_PER_SEC);
}

static int manager_ovs_on_monitor_initial(
                OVSDBClient *client,
                sd_json_variant *result,
                sd_json_variant *error,
                void *userdata) {

        Manager *m = ASSERT_PTR(userdata);
        int r;

        /* When the connection drops to FAILED, manager_ovs_state_changed runs first
         * and calls manager_ovs_schedule_reconnect, which unrefs the client and so
         * fires this callback via cancel_all with synthetic NULL result+error. If we
         * scheduled a reconnect again here we would unref twice, double-bump the
         * backoff (1s→4s instead of 1s→2s) and arm a duplicate timer. */
        if (!m->ovsdb)
                return 0;

        if (error) {
                _cleanup_free_ char *text = NULL;
                (void) sd_json_variant_format(error, 0, &text);
                log_warning("OVSDB monitor_cond failed: %s, will reconnect", strna(text));
                manager_ovs_schedule_reconnect(m);
                return 0;
        }

        if (!result) {
                /* Both result and error NULL: monitor subscription failed internally
                 * (OOM, or monitor_cache apply failure). Treat as failure and reconnect. */
                log_warning("OVSDB monitor_cond produced no result, scheduling reconnect");
                manager_ovs_schedule_reconnect(m);
                return 0;
        }

        log_debug("OVSDB monitor initial snapshot received, reconciling");

        /* Check the per-boot ovs-cleared marker. Only ENOENT means "not cleared this
         * boot yet, do the wipe"; other errors (EACCES on a hostile/broken /run, EIO,
         * etc.) should not silently re-trigger the wipe — log and skip the clear. */
        bool need_clear = false;
        if (m->ovs_clear_on_boot) {
                if (access("/run/systemd/netif/ovs-cleared", F_OK) < 0) {
                        if (errno == ENOENT)
                                need_clear = true;
                        else
                                log_warning_errno(errno,
                                                  "Failed to stat /run/systemd/netif/ovs-cleared, skipping ClearDatabaseOnBoot wipe: %m");
                }
        }
        if (need_clear) {
                /* First boot with ClearDatabaseOnBoot=yes: wipe and re-create.
                 * Marker file and reconciliation are set up from ovs_clear_done(). */
                r = ovs_clear_database(m);
                if (r < 0) {
                        log_warning_errno(r, "OVS database clear failed, falling back to reconcile: %m");
                        r = ovs_reconcile(m);
                        if (r < 0)
                                log_warning_errno(r, "OVS reconciliation failed: %m");
                }
        } else {
                r = ovs_reconcile(m);
                if (r < 0)
                        log_warning_errno(r, "OVS reconciliation failed: %m");
        }

        return 0;
}

static int manager_ovs_reconnect_handler(sd_event_source *s, uint64_t usec, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        m->ovs_reconnect_timer = sd_event_source_disable_unref(m->ovs_reconnect_timer);

        log_debug("OVS reconnect timer fired, attempting reconnect");
        (void) manager_ovs_maybe_start(m);
        return 0;
}

static void manager_ovs_on_update(OVSDBClient *client, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        /* Monitor cache was updated — re-reconcile to pick up deferred
         * .network attachments that were waiting for a bridge to appear.
         *
         * BUT: every transact we send to OVSDB also produces an update2
         * notification on the same connection (the server broadcasts row
         * changes to all subscribed monitors, including the one that caused
         * them). If we re-entered ovs_reconcile() here we would re-emit the
         * same UPDATE rows, the server would echo another update2, and we'd
         * spin in a back-to-back transact storm until idempotency happened
         * to produce no further row changes. Suppress while we have any
         * transact in flight; ovs_reconcile_done drains the counter and
         * picks up the unified ovs_reconcile_pending flag if anything
         * coalesced during the in-flight window. */
        if (m->ovs_inflight_transacts > 0) {
                log_debug("OVSDB update arrived while %u transact(s) in flight, suppressing self-induced reconcile",
                          m->ovs_inflight_transacts);
                /* Mark pending so the in-flight transact's *_done callback
                 * runs reconcile after draining — that's the only way to
                 * guarantee externally-relevant updates aren't lost. */
                m->ovs_reconcile_pending = true;
                return;
        }

        /* Drain any coalesced pending reconcile (cleared by us; ovs_reconcile
         * still runs unconditionally because some externally-triggered update
         * may have caused this callback even with no pending flag set).
         * Do NOT clear ovs_pending_teardown here: teardown is managed by
         * ovs_reconcile_done and manager_ovs_maybe_start. */
        m->ovs_reconcile_pending = false;

        log_debug("OVSDB monitor cache updated, re-reconciling");
        r = ovs_reconcile(m);
        if (r < 0)
                log_warning_errno(r, "OVS re-reconciliation after monitor update failed: %m");
}

static int manager_ovs_state_changed(
                OVSDBClient *client,
                OVSDBClientState old_state,
                OVSDBClientState new_state,
                void *userdata) {

        Manager *m = ASSERT_PTR(userdata);

        if (new_state == OVSDB_CLIENT_READY) {
                int r;

                m->ovs_reconnect_delay = 1 * USEC_PER_SEC; /* reset backoff */

                log_debug("Connected to OVSDB at '%s'",
                          m->ovs_socket_path ?: OVS_DEFAULT_SOCKET_PATH);

                /* Subscribe to monitor updates; reconcile runs after the initial snapshot arrives */
                r = ovsdb_client_monitor_cond(client, manager_ovs_on_monitor_initial, m);
                if (r < 0) {
                        log_warning_errno(r, "Failed to subscribe to OVSDB monitor, scheduling reconnect: %m");

                        /* Without a monitor subscription the client is READY but
                         * useless: ovs_reconcile() returns 0 silently because the
                         * monitor cache is NULL, the snapshot callback was never
                         * installed so it'll never arrive, and we'd silently miss
                         * every later reload/link-trigger reconcile. Drop the
                         * client and arm the reconnect timer so the next attempt
                         * gets a fresh client and another monitor_cond. */
                        manager_ovs_schedule_reconnect(m);
                }
        } else if (new_state == OVSDB_CLIENT_FAILED)
                manager_ovs_schedule_reconnect(m);

        return 0;
}

/* Create, bind and start a fresh OVSDB client. Caller must ensure m->ovsdb is NULL. */
static int manager_ovs_connect(Manager *m) {
        const char *socket_path;
        int r;

        assert(m);
        assert(!m->ovsdb);

        /* A reconnect timer may still be armed from a prior failure; disable it so it cannot
         * later fire and re-enter maybe_start() on the client we are about to create. */
        m->ovs_reconnect_timer = sd_event_source_disable_unref(m->ovs_reconnect_timer);

        if (m->ovs_reconnect_delay == 0)
                m->ovs_reconnect_delay = 1 * USEC_PER_SEC;

        socket_path = m->ovs_socket_path ?: OVS_DEFAULT_SOCKET_PATH;
        r = ovsdb_client_new(&m->ovsdb, m->event, socket_path);
        if (r < 0) {
                /* Arm the reconnect timer rather than giving up, so a transient allocation/socket
                 * failure is retried instead of leaving OVS unconfigured until the next reload. */
                log_warning_errno(r, "Failed to create OVSDB client, will retry: %m");
                manager_ovs_schedule_reconnect(m);
                return 0;
        }

        ovsdb_client_set_userdata(m->ovsdb, m);
        ovsdb_client_bind_state_change(m->ovsdb, manager_ovs_state_changed);
        ovsdb_client_bind_update(m->ovsdb, manager_ovs_on_update);

        r = ovsdb_client_start(m->ovsdb);
        if (r < 0) {
                log_warning_errno(r, "Failed to start OVSDB client, will retry: %m");
                /* A get_schema send failure already transitioned the client to FAILED,
                 * whose state callback ran manager_ovs_schedule_reconnect() and dropped
                 * m->ovsdb. Only the earlier connect()/attach_event() failures return here
                 * with the client still live and no reconnect scheduled yet. */
                if (m->ovsdb)
                        manager_ovs_schedule_reconnect(m);
                return 0; /* don't propagate error — retry scheduled */
        }

        log_debug("OVSDB client started, handshaking... (ovs_use_count=%u)", m->ovs_use_count);
        return 0;
}

int manager_ovs_maybe_start(Manager *m) {
        int r;

        assert(m);

        manager_count_ovs_usage(m);

        if (m->ovs_use_count == 0) {
                /* The last OVS config was removed. If we have a live READY client, run one final
                 * reconcile: with empty desired state ovs_reconcile() emits only DELETE ops, which
                 * sweep the rows we created out of OVSDB. The client drop is deferred to
                 * ovs_reconcile_done() once that transact is acknowledged, so the bytes actually
                 * reach the server instead of being discarded by cancel_all() in the unref.
                 *
                 * If we are not connected, we simply drop the client: any rows we left behind are
                 * tagged networkd-managed=true and get reclaimed by the orphan sweep (Phase 0 of
                 * ovs_reconcile) on the next reconcile that runs with a live connection. We do not
                 * reconnect purely to delete — OVS's own IDL likewise ties the connection lifetime
                 * to "is OVSDB still needed" and relies on recompute-and-retry, not a bespoke
                 * delete-replay state machine. */
                if (m->ovsdb && ovsdb_client_get_state(m->ovsdb) == OVSDB_CLIENT_READY) {
                        m->ovs_pending_teardown = true;
                        r = ovs_reconcile(m);
                        if (r < 0)
                                log_warning_errno(r, "Final OVS reconcile before teardown failed, tearing down anyway: %m");
                        else if (m->ovs_inflight_transacts > 0)
                                return 0;  /* deferred: ovs_reconcile_done drains it on ACK */
                        /* Nothing to sweep (no managed rows) — clear and fall through to drop. */
                        m->ovs_pending_teardown = false;
                }

                m->ovs_reconnect_timer = sd_event_source_disable_unref(m->ovs_reconnect_timer);
                m->ovs_reconnect_delay = 0;
                m->ovs_inflight_transacts = 0;
                m->ovs_reconcile_pending = false;
                m->ovs_pending_teardown = false;
                manager_ovs_drop_client(m);
                return 0;
        }

        /* OVS configs were re-added (or first-arrived). Cancel any deferred teardown so the next
         * ovs_reconcile_done doesn't drop the client we are about to use. */
        m->ovs_pending_teardown = false;

        if (m->ovsdb) {
                /* Client already exists. If it's READY, re-reconcile to pick up config changes. */
                if (ovsdb_client_get_state(m->ovsdb) == OVSDB_CLIENT_READY) {
                        r = ovs_reconcile(m);
                        if (r < 0)
                                log_warning_errno(r, "OVS re-reconciliation after reload failed: %m");
                }
                return 0;
        }

        /* No client yet (first start, or a prior FAILED transition dropped it). */
        return manager_ovs_connect(m);
}
