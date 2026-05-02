/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fs-util.h"
#include "hashmap.h"
#include "in-addr-util.h"
#include "netdev.h"
#include "networkd-link.h"
#include "networkd-manager.h"
#include "networkd-network.h"
#include "networkd-ovs.h"
#include "ovsdb/ovsdb-client.h"
#include "ovsdb/ovsdb-monitor.h"
#include "ovsdb/ovsdb-ops.h"
#include "ovs-bridge.h"
#include "ovs-port.h"
#include "ovs-tunnel.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "vlan-util.h"

/* Extract a value from an OVSDB map-encoded column.
 * Map encoding: ["map", [["k1","v1"], ["k2","v2"], ...]] */
static const char* ovs_get_external_id(sd_json_variant *row, const char *key) {
        sd_json_variant *ext_ids, *map_tag, *pairs;

        assert(row);
        assert(key);

        ext_ids = sd_json_variant_by_key(row, "external_ids");
        if (!ext_ids || sd_json_variant_elements(ext_ids) != 2)
                return NULL;

        map_tag = sd_json_variant_by_index(ext_ids, 0);
        if (!map_tag || !sd_json_variant_is_string(map_tag) ||
            !streq(sd_json_variant_string(map_tag), "map"))
                return NULL;

        pairs = sd_json_variant_by_index(ext_ids, 1);
        if (!pairs || !sd_json_variant_is_array(pairs))
                return NULL;

        for (size_t i = 0; i < sd_json_variant_elements(pairs); i++) {
                sd_json_variant *pair, *k, *v;

                pair = sd_json_variant_by_index(pairs, i);
                if (!pair || !sd_json_variant_is_array(pair) || sd_json_variant_elements(pair) != 2)
                        continue;

                k = sd_json_variant_by_index(pair, 0);
                v = sd_json_variant_by_index(pair, 1);

                if (k && v &&
                    sd_json_variant_is_string(k) && sd_json_variant_is_string(v) &&
                    streq(sd_json_variant_string(k), key))
                        return sd_json_variant_string(v);
        }

        return NULL;
}

struct ovs_delete_ctx {
        Manager *m;
        sd_json_variant **ops;
        int error;
};

static void ovs_check_bridge_delete(const char *uuid, sd_json_variant *row, void *userdata) {
        struct ovs_delete_ctx *ctx = userdata;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *where = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *delete_op = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *ovs_where = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *mutations = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *mutate_op = NULL;
        sd_json_variant *name_v;
        const char *managed, *name;
        NetDev *netdev;
        int r;

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
        Network *network;
        ORDERED_HASHMAP_FOREACH(network, ctx->m->networks) {
                if (network->ovs_bridge_name && streq(network->ovs_bridge_name, name))
                        return;
        }

        log_debug("OVS bridge '%s' (uuid=%s) no longer in config, queuing delete", name, uuid);

        /* Mutate Open_vSwitch: bridges -= ["set", [["uuid", "<uuid>"]]]
         * Must come before the DELETE — drop the strong reference first. */
        r = ovsdb_where_all(&ovs_where);
        if (r < 0)
                goto fail;

        r = sd_json_build(
                        &mutations,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_STRING("bridges"),
                                        SD_JSON_BUILD_STRING("delete"),
                                        SD_JSON_BUILD_ARRAY(
                                                SD_JSON_BUILD_STRING("set"),
                                                SD_JSON_BUILD_ARRAY(
                                                        SD_JSON_BUILD_ARRAY(
                                                                SD_JSON_BUILD_STRING("uuid"),
                                                                SD_JSON_BUILD_STRING(uuid)))))));
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

static void ovs_check_port_delete(const char *uuid, sd_json_variant *row, void *userdata) {
        struct ovs_delete_ctx *ctx = userdata;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *where = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *delete_op = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *ovs_where = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *port_uuid_ref = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *mutations = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *mutate_op = NULL;
        sd_json_variant *name_v;
        const char *managed, *name;
        int r;

        if (ctx->error < 0)
                return;

        managed = ovs_get_external_id(row, "networkd-managed");
        if (!managed || !streq(managed, "true"))
                return;

        name_v = sd_json_variant_by_key(row, "name");
        if (!name_v || !sd_json_variant_is_string(name_v))
                return;
        name = sd_json_variant_string(name_v);

        if (ovs_port_still_configured(ctx->m, name))
                return;

        log_debug("OVS port '%s' (uuid=%s) no longer in config, queuing delete", name, uuid);

        /* Mutate all Bridge rows: ports -= this port UUID.
         * Bridge.ports is a strong reference — must be removed before DELETE.
         * Since port UUIDs are globally unique, this is a no-op for non-parent bridges. */
        r = ovsdb_where_all(&ovs_where);
        if (r < 0)
                goto fail;

        r = sd_json_build(&port_uuid_ref,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_STRING("uuid"),
                                SD_JSON_BUILD_STRING(uuid)));
        if (r < 0)
                goto fail;

        r = sd_json_build(&mutations,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_STRING("ports"),
                                        SD_JSON_BUILD_STRING("delete"),
                                        SD_JSON_BUILD_ARRAY(
                                                SD_JSON_BUILD_STRING("set"),
                                                SD_JSON_BUILD_ARRAY(
                                                        SD_JSON_BUILD_VARIANT(port_uuid_ref))))));
        if (r < 0)
                goto fail;

        r = ovsdb_op_mutate("Bridge", ovs_where, mutations, &mutate_op);
        if (r < 0)
                goto fail;

        r = sd_json_variant_append_array(ctx->ops, mutate_op);
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
        const char *name;
        bool found;
        const char *uuid;  /* Set to the UUID when found */
};

static void ovs_check_name_cb(const char *uuid, sd_json_variant *row, void *userdata) {
        struct ovs_name_check *check = userdata;

        /* Hashmap iteration order is unspecified; if two rows transiently share a name
         * (mid-rename, or stale row pending GC) the last-seen wins arbitrarily. Stop on
         * first match so subsequent UPDATE/UPSERT decisions are deterministic. */
        if (check->found)
                return;

        sd_json_variant *name_v = sd_json_variant_by_key(row, "name");
        if (name_v && sd_json_variant_is_string(name_v) &&
            streq(sd_json_variant_string(name_v), check->name)) {
                check->found = true;
                check->uuid = uuid;
        }
}

/* Callback for ovs_ensure_port_bridge_membership: scans Bridge rows, finds the one
 * whose `ports` set contains the target port UUID. Stores the bridge's name on match. */
struct ovs_find_port_bridge_ctx {
        const char *port_uuid;
        const char *found_bridge_name;  /* aliases monitor cache; copy if retained */
};

static void ovs_find_port_bridge_cb(const char *uuid, sd_json_variant *row, void *userdata) {
        struct ovs_find_port_bridge_ctx *ctx = userdata;
        sd_json_variant *ports_col, *tag, *val, *name;

        if (ctx->found_bridge_name)
                return;  /* already matched */

        ports_col = sd_json_variant_by_key(row, "ports");
        if (!ports_col || !sd_json_variant_is_array(ports_col) ||
            sd_json_variant_elements(ports_col) != 2)
                return;

        tag = sd_json_variant_by_index(ports_col, 0);
        val = sd_json_variant_by_index(ports_col, 1);
        if (!tag || !sd_json_variant_is_string(tag) || !val)
                return;

        /* Per RFC 7047 §5.1, a uuid-set column with exactly one element MAY be
         * encoded as the bare atom ["uuid", "X"] instead of the multi-element
         * wrapper ["set", [["uuid","X"]]]. ovs-vswitchd in practice always wraps
         * for max=unlimited columns like Bridge.ports, but accept both forms. */
        if (streq(sd_json_variant_string(tag), "uuid") && sd_json_variant_is_string(val)) {
                if (streq(sd_json_variant_string(val), ctx->port_uuid)) {
                        name = sd_json_variant_by_key(row, "name");
                        if (name && sd_json_variant_is_string(name))
                                ctx->found_bridge_name = sd_json_variant_string(name);
                }
                return;
        }

        if (!streq(sd_json_variant_string(tag), "set") || !sd_json_variant_is_array(val))
                return;

        for (size_t i = 0; i < sd_json_variant_elements(val); i++) {
                sd_json_variant *pair = sd_json_variant_by_index(val, i);
                sd_json_variant *ptag, *puuid;

                if (!pair || !sd_json_variant_is_array(pair) ||
                    sd_json_variant_elements(pair) != 2)
                        continue;

                ptag = sd_json_variant_by_index(pair, 0);
                puuid = sd_json_variant_by_index(pair, 1);
                if (!ptag || !sd_json_variant_is_string(ptag) ||
                    !streq(sd_json_variant_string(ptag), "uuid"))
                        continue;
                if (!puuid || !sd_json_variant_is_string(puuid))
                        continue;

                if (streq(sd_json_variant_string(puuid), ctx->port_uuid)) {
                        name = sd_json_variant_by_key(row, "name");
                        if (name && sd_json_variant_is_string(name))
                                ctx->found_bridge_name = sd_json_variant_string(name);
                        return;
                }
        }
}

/* Emit a Bridge.ports mutate op that inserts or deletes a port UUID reference. */
static int ovs_emit_bridge_port_mutate(
                const char *bridge_name,
                const char *port_uuid,
                const char *op_verb,  /* "insert" or "delete" */
                sd_json_variant **ops) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *where = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *mutations = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *mutate_op = NULL;
        int r;

        r = sd_json_build(&where,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_STRING("name"),
                                        SD_JSON_BUILD_STRING("=="),
                                        SD_JSON_BUILD_STRING(bridge_name))));
        if (r < 0)
                return r;

        r = sd_json_build(&mutations,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_STRING("ports"),
                                        SD_JSON_BUILD_STRING(op_verb),
                                        SD_JSON_BUILD_ARRAY(
                                                SD_JSON_BUILD_STRING("set"),
                                                SD_JSON_BUILD_ARRAY(
                                                        SD_JSON_BUILD_ARRAY(
                                                                SD_JSON_BUILD_STRING("uuid"),
                                                                SD_JSON_BUILD_STRING(port_uuid)))))));
        if (r < 0)
                return r;

        r = ovsdb_op_mutate("Bridge", where, mutations, &mutate_op);
        if (r < 0)
                return r;

        return sd_json_variant_append_array(ops, mutate_op);
}

/* Ensure the Port identified by port_uuid is attached to desired_bridge.
 * If it's currently in a different bridge, emit mutate ops to remove it from the
 * old bridge and add it to the new one. No-op if already attached to desired_bridge. */
static int ovs_ensure_port_bridge_membership(
                Manager *m,
                const char *port_uuid,
                const char *desired_bridge,
                sd_json_variant **ops) {

        OVSDBMonitor *mon;
        struct ovs_find_port_bridge_ctx ctx;
        _cleanup_free_ char *current_bridge = NULL;
        int r;

        assert(m);
        assert(port_uuid);
        assert(desired_bridge);
        assert(ops);

        mon = m->ovsdb ? ovsdb_client_get_monitor(m->ovsdb) : NULL;
        if (!mon)
                return 0;

        ctx = (struct ovs_find_port_bridge_ctx) { .port_uuid = port_uuid };
        ovsdb_monitor_foreach(mon, "Bridge", ovs_find_port_bridge_cb, &ctx);

        if (ctx.found_bridge_name && streq(ctx.found_bridge_name, desired_bridge))
                return 0;  /* already correctly attached */

        /* Copy name before dropping the cache alias (defensive against mid-op invalidation) */
        if (ctx.found_bridge_name) {
                current_bridge = strdup(ctx.found_bridge_name);
                if (!current_bridge)
                        return log_oom();

                r = ovs_emit_bridge_port_mutate(current_bridge, port_uuid, "delete", ops);
                if (r < 0)
                        return r;
        }

        return ovs_emit_bridge_port_mutate(desired_bridge, port_uuid, "insert", ops);
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

        check = (struct ovs_name_check) { .name = bridge_name };
        ovsdb_monitor_foreach(mon, "Bridge", ovs_check_name_cb, &check);
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
static const char* ovs_monitor_port_name_by_uuid(OVSDBMonitor *mon, const char *uuid) {
        sd_json_variant *row, *name;

        row = ovsdb_monitor_get(mon, "Port", uuid);
        if (!row)
                return NULL;

        name = sd_json_variant_by_key(row, "name");
        if (!name || !sd_json_variant_is_string(name))
                return NULL;

        return sd_json_variant_string(name);
}

int ovs_monitor_get_bridge_ports(Manager *m, const char *bridge_name, char ***ret_ports) {
        _cleanup_strv_free_ char **ports = NULL;
        OVSDBMonitor *mon;
        sd_json_variant *row, *ports_col, *tag, *val;
        struct ovs_name_check check;
        int r;

        assert(m);
        assert(bridge_name);
        assert(ret_ports);

        *ret_ports = NULL;

        mon = m->ovsdb ? ovsdb_client_get_monitor(m->ovsdb) : NULL;
        if (!mon)
                return 0;

        check = (struct ovs_name_check) { .name = bridge_name };
        ovsdb_monitor_foreach(mon, "Bridge", ovs_check_name_cb, &check);
        if (!check.found)
                return 0;

        row = ovsdb_monitor_get(mon, "Bridge", check.uuid);
        if (!row)
                return 0;

        ports_col = sd_json_variant_by_key(row, "ports");
        if (!ports_col || !sd_json_variant_is_array(ports_col) ||
            sd_json_variant_elements(ports_col) != 2)
                return 0;

        tag = sd_json_variant_by_index(ports_col, 0);
        val = sd_json_variant_by_index(ports_col, 1);
        if (!tag || !sd_json_variant_is_string(tag) || !val)
                return 0;

        /* Per RFC 7047 §5.1, accept both encodings: bare ["uuid", "X"] singleton
         * and ["set", [["uuid","X"], ...]] multi-element wrapper. ovs-vswitchd
         * always wraps for max=unlimited columns in practice; this is defensive. */
        if (streq(sd_json_variant_string(tag), "uuid") && sd_json_variant_is_string(val)) {
                const char *name = ovs_monitor_port_name_by_uuid(mon, sd_json_variant_string(val));
                if (name) {
                        r = strv_extend(&ports, name);
                        if (r < 0)
                                return r;
                }
                *ret_ports = TAKE_PTR(ports);
                return 0;
        }

        if (!streq(sd_json_variant_string(tag), "set") || !sd_json_variant_is_array(val))
                return 0;

        for (size_t i = 0; i < sd_json_variant_elements(val); i++) {
                sd_json_variant *pair = sd_json_variant_by_index(val, i);
                sd_json_variant *ptag, *puuid;

                if (!pair || !sd_json_variant_is_array(pair) ||
                    sd_json_variant_elements(pair) != 2)
                        continue;

                ptag = sd_json_variant_by_index(pair, 0);
                puuid = sd_json_variant_by_index(pair, 1);
                if (!ptag || !sd_json_variant_is_string(ptag) ||
                    !streq(sd_json_variant_string(ptag), "uuid"))
                        continue;
                if (!puuid || !sd_json_variant_is_string(puuid))
                        continue;

                const char *name = ovs_monitor_port_name_by_uuid(mon, sd_json_variant_string(puuid));
                if (name) {
                        r = strv_extend(&ports, name);
                        if (r < 0)
                                return r;
                }
        }

        *ret_ports = TAKE_PTR(ports);
        return 0;
}

/* RFC 7047 §5.1: named-uuid must match [a-zA-Z_][a-zA-Z0-9_]* */
static char* ovs_make_uuid_name(const char *prefix, const char *ifname) {
        char *name;

        assert(prefix);
        assert(ifname);

        name = strjoin(prefix, ifname);
        if (!name)
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
                                SD_JSON_BUILD_STRING("set"),
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
                                SD_JSON_BUILD_STRING("map"),
                                SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_ARRAY(
                                                SD_JSON_BUILD_STRING("networkd-managed"),
                                                SD_JSON_BUILD_STRING("true")),
                                        SD_JSON_BUILD_ARRAY(
                                                SD_JSON_BUILD_STRING("networkd-config"),
                                                SD_JSON_BUILD_STRING(strempty(config_file))),
                                        SD_JSON_BUILD_ARRAY(
                                                SD_JSON_BUILD_STRING("networkd-version"),
                                                SD_JSON_BUILD_STRING(OVS_NETWORKD_VERSION)))));
}

static int ovs_build_named_uuid_ref(const char *id, sd_json_variant **ret) {
        assert(id);
        assert(ret);

        return sd_json_build(
                        ret,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_STRING("named-uuid"),
                                SD_JSON_BUILD_STRING(id)));
}

static int ovs_reconcile_bridge(Manager *m, NetDev *netdev, sd_json_variant **ops) {
        OVSBridge *b;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *external_ids = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *iface_row = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *iface_op = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *iface_ref = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *port_row = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *port_op = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *port_ref = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *bridge_row = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *bridge_op = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *bridge_ref = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *where = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *mutations = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *mutate_op = NULL;
        _cleanup_free_ char *iface_uuid_name = NULL;
        _cleanup_free_ char *port_uuid_name = NULL;
        _cleanup_free_ char *bridge_uuid_name = NULL;
        int r;

        assert(netdev);
        assert(ops);

        b = OVS_BRIDGE(netdev);

        /* If bridge already exists in monitor cache, UPDATE instead of INSERT */
        OVSDBMonitor *mon = ovsdb_client_get_monitor(m->ovsdb);
        if (mon) {
                struct ovs_name_check check = { .name = netdev->ifname };
                ovsdb_monitor_foreach(mon, "Bridge", ovs_check_name_cb, &check);
                if (check.found) {
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *update_row = NULL;
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *update_where = NULL;
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *update_op = NULL;
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *update_ext = NULL;
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *update_protocols = NULL;

                        log_netdev_debug(netdev, "OVS bridge '%s' already exists, updating", strna(netdev->ifname));

                        r = ovs_build_external_ids(netdev->filename, &update_ext);
                        if (r < 0)
                                return r;

                        /* Build protocols set: ["set", [...protos]] when set, ["set", []] when removed */
                        if (!strv_isempty(b->protocols)) {
                                _cleanup_(sd_json_variant_unrefp) sd_json_variant *inner = NULL;
                                STRV_FOREACH(p, b->protocols) {
                                        r = sd_json_variant_append_arrayb(&inner, SD_JSON_BUILD_STRING(*p));
                                        if (r < 0)
                                                return r;
                                }
                                r = sd_json_build(&update_protocols,
                                                SD_JSON_BUILD_ARRAY(
                                                        SD_JSON_BUILD_STRING("set"),
                                                        SD_JSON_BUILD_VARIANT(inner)));
                        } else
                                r = ovs_build_empty_set(&update_protocols);
                        if (r < 0)
                                return r;

                        /* Optional columns: emit unconditionally so removed config values
                         * reset the OVSDB column instead of leaving stale state behind. */
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *fail_mode_v = NULL;
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *datapath_id_v = NULL;

                        r = ovs_build_optional_string(b->fail_mode, &fail_mode_v);
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
        if (!strv_isempty(b->protocols)) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *inner = NULL;
                STRV_FOREACH(p, b->protocols) {
                        r = sd_json_variant_append_arrayb(&inner, SD_JSON_BUILD_STRING(*p));
                        if (r < 0)
                                return r;
                }
                r = sd_json_build(&protocols_set,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_STRING("set"),
                                SD_JSON_BUILD_VARIANT(inner)));
                if (r < 0)
                        return r;
        }

        r = sd_json_buildo(
                        &bridge_row,
                        SD_JSON_BUILD_PAIR_STRING("name", netdev->ifname),
                        SD_JSON_BUILD_PAIR_VARIANT("ports", port_ref),
                        SD_JSON_BUILD_PAIR_CONDITION(!!b->fail_mode, "fail_mode", SD_JSON_BUILD_STRING(strempty(b->fail_mode))),
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
                                        SD_JSON_BUILD_STRING("bridges"),
                                        SD_JSON_BUILD_STRING("insert"),
                                        SD_JSON_BUILD_ARRAY(
                                                SD_JSON_BUILD_STRING("set"),
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
                                SD_JSON_BUILD_STRING("set"),
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
                sd_json_variant **ops) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *external_ids = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *iface_set = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *port_row = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *port_op = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *port_ref = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *where = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *mutations = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *mutate_op = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *trunks_set = NULL;
        _cleanup_free_ char *port_uuid_name = NULL;
        int r;

        assert(netdev);
        assert(p);
        assert(members);
        assert(ops);

        /* If bond port already exists in monitor cache, UPDATE */
        OVSDBMonitor *mon = ovsdb_client_get_monitor(m->ovsdb);
        if (mon) {
                struct ovs_name_check check = { .name = netdev->ifname };
                ovsdb_monitor_foreach(mon, "Port", ovs_check_name_cb, &check);
                if (check.found) {
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *update_row = NULL;
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *update_where = NULL;
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *update_op = NULL;
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *update_ext = NULL;
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *update_trunks = NULL;
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *update_iface_refs = NULL;
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *update_iface_set = NULL;

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
                                struct ovs_name_check ifcheck = { .name = *member };

                                ovsdb_monitor_foreach(mon, "Interface", ovs_check_name_cb, &ifcheck);

                                if (ifcheck.found) {
                                        /* Reuse existing Interface by UUID */
                                        r = sd_json_build(&iface_ref,
                                                        SD_JSON_BUILD_ARRAY(
                                                                SD_JSON_BUILD_STRING("uuid"),
                                                                SD_JSON_BUILD_STRING(ifcheck.uuid)));
                                        if (r < 0)
                                                return r;
                                } else {
                                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *iface_row = NULL;
                                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *iface_op = NULL;
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
                                                SD_JSON_BUILD_STRING("set"),
                                                SD_JSON_BUILD_VARIANT(update_iface_refs)));
                        if (r < 0)
                                return r;

                        /* Always emit optional columns so removed config resets the OVSDB column */
                        if (!update_trunks) {
                                r = ovs_build_empty_set(&update_trunks);
                                if (r < 0)
                                        return r;
                        }

                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *tag_v = NULL;
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *vlan_mode_v = NULL;
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *lacp_v = NULL;
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *bond_mode_v = NULL;

                        r = ovs_build_optional_int(p->tag, p->tag != VLANID_INVALID, &tag_v);
                        if (r < 0)
                                return r;
                        r = ovs_build_optional_string(p->vlan_mode, &vlan_mode_v);
                        if (r < 0)
                                return r;
                        r = ovs_build_optional_string(p->lacp, &lacp_v);
                        if (r < 0)
                                return r;
                        r = ovs_build_optional_string(p->bond_mode, &bond_mode_v);
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
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *iface_row = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *iface_op = NULL;
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *iface_ref = NULL;
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
                                SD_JSON_BUILD_STRING("set"),
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
                        SD_JSON_BUILD_PAIR_CONDITION(!!p->vlan_mode, "vlan_mode", SD_JSON_BUILD_STRING(p->vlan_mode)),
                        SD_JSON_BUILD_PAIR_CONDITION(!!trunks_set, "trunks", SD_JSON_BUILD_VARIANT(trunks_set)),
                        SD_JSON_BUILD_PAIR_CONDITION(!!p->lacp, "lacp", SD_JSON_BUILD_STRING(p->lacp)),
                        SD_JSON_BUILD_PAIR_CONDITION(!!p->bond_mode, "bond_mode", SD_JSON_BUILD_STRING(p->bond_mode)),
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
                                        SD_JSON_BUILD_STRING("name"),
                                        SD_JSON_BUILD_STRING("=="),
                                        SD_JSON_BUILD_STRING(p->bridge))));
        if (r < 0)
                return r;

        r = sd_json_build(
                        &mutations,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_STRING("ports"),
                                        SD_JSON_BUILD_STRING("insert"),
                                        SD_JSON_BUILD_ARRAY(
                                                SD_JSON_BUILD_STRING("set"),
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

static int ovs_reconcile_port(Manager *m, NetDev *netdev, sd_json_variant **ops) {
        OVSPort *p;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *external_ids = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *iface_row = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *iface_op = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *iface_ref = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *port_row = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *port_op = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *port_ref = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *where = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *mutations = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *mutate_op = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *trunks_set = NULL;
        _cleanup_free_ char *iface_uuid_name = NULL;
        _cleanup_free_ char *port_uuid_name = NULL;
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
                                struct ovs_name_check check = { .name = netdev->ifname };
                                ovsdb_monitor_foreach(mon, "Port", ovs_check_name_cb, &check);
                                if (check.found) {
                                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *del_where = NULL;
                                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *delete_op = NULL;

                                        log_netdev_debug(netdev, "OVS bond '%s' has no member interfaces, deleting stale Port row",
                                                         strna(netdev->ifname));

                                        /* Unlink from owning bridge first (strong ref) */
                                        r = ovs_emit_bridge_port_mutate(p->bridge, check.uuid, "delete", ops);
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

                return ovs_reconcile_bond_port(m, netdev, p, bond_members, ops);
        }

        /* If port already exists in monitor cache, UPDATE instead of INSERT */
        OVSDBMonitor *mon = ovsdb_client_get_monitor(m->ovsdb);
        if (mon) {
                struct ovs_name_check check = { .name = netdev->ifname };
                ovsdb_monitor_foreach(mon, "Port", ovs_check_name_cb, &check);
                if (check.found) {
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *update_row = NULL;
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *update_where = NULL;
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *update_op = NULL;
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *update_ext = NULL;
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *update_trunks = NULL;

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
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *tag_v = NULL;
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *vlan_mode_v = NULL;

                        r = ovs_build_optional_int(p->tag, p->tag != VLANID_INVALID, &tag_v);
                        if (r < 0)
                                return r;
                        r = ovs_build_optional_string(p->vlan_mode, &vlan_mode_v);
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
                                struct ovs_name_check ifcheck = { .name = netdev->ifname };

                                ovsdb_monitor_foreach(mon, "Interface", ovs_check_name_cb, &ifcheck);
                                if (ifcheck.found) {
                                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *iface_options = NULL;
                                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *iface_row_update = NULL;
                                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *iface_where_update = NULL;
                                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *iface_update_op = NULL;
                                        const char *iface_type_now;

                                        if (p->type == OVS_PORT_TYPE_PATCH && p->peer_port) {
                                                iface_type_now = "patch";
                                                r = sd_json_build(
                                                                &iface_options,
                                                                SD_JSON_BUILD_ARRAY(
                                                                        SD_JSON_BUILD_STRING("map"),
                                                                        SD_JSON_BUILD_ARRAY(
                                                                                SD_JSON_BUILD_ARRAY(
                                                                                        SD_JSON_BUILD_STRING("peer"),
                                                                                        SD_JSON_BUILD_STRING(p->peer_port)))));
                                        } else {
                                                /* internal port (or patch with missing peer) — clear options */
                                                iface_type_now = "internal";
                                                r = sd_json_build(
                                                                &iface_options,
                                                                SD_JSON_BUILD_ARRAY(
                                                                        SD_JSON_BUILD_STRING("map"),
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
                                                SD_JSON_BUILD_STRING("map"),
                                                SD_JSON_BUILD_ARRAY(
                                                        SD_JSON_BUILD_ARRAY(
                                                                SD_JSON_BUILD_STRING("peer"),
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
                        SD_JSON_BUILD_PAIR_CONDITION(!!p->vlan_mode, "vlan_mode", SD_JSON_BUILD_STRING(p->vlan_mode)),
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
                                        SD_JSON_BUILD_STRING("name"),
                                        SD_JSON_BUILD_STRING("=="),
                                        SD_JSON_BUILD_STRING(p->bridge))));
        if (r < 0)
                return r;

        r = sd_json_build(
                        &mutations,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_STRING("ports"),
                                        SD_JSON_BUILD_STRING("insert"),
                                        SD_JSON_BUILD_ARRAY(
                                                SD_JSON_BUILD_STRING("set"),
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
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *external_ids = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *options = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *iface_row = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *iface_op = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *iface_ref = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *port_row = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *port_op = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *port_ref = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *where = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *mutations = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *mutate_op = NULL;
        _cleanup_free_ char *iface_uuid_name = NULL;
        _cleanup_free_ char *port_uuid_name = NULL;
        _cleanup_free_ char *remote_str = NULL;
        _cleanup_free_ char *local_str = NULL;
        _cleanup_free_ char *key_str = NULL;
        int r;

        assert(netdev);
        assert(ops);

        t = OVS_TUNNEL(netdev);

        /* Check if tunnel port already exists in monitor cache */
        OVSDBMonitor *mon = ovsdb_client_get_monitor(m->ovsdb);
        bool tunnel_exists = false;
        _cleanup_free_ char *tunnel_port_uuid = NULL;
        if (mon) {
                struct ovs_name_check check = { .name = netdev->ifname };
                ovsdb_monitor_foreach(mon, "Port", ovs_check_name_cb, &check);
                tunnel_exists = check.found;
                if (check.uuid) {
                        tunnel_port_uuid = strdup(check.uuid);
                        if (!tunnel_port_uuid)
                                return log_oom();
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
                                        SD_JSON_BUILD_STRING("remote_ip"),
                                        SD_JSON_BUILD_STRING(remote_str)));
                if (r < 0)
                        return r;

                if (local_str) {
                        r = sd_json_variant_append_arrayb(
                                        &opts_inner,
                                        SD_JSON_BUILD_ARRAY(
                                                SD_JSON_BUILD_STRING("local_ip"),
                                                SD_JSON_BUILD_STRING(local_str)));
                        if (r < 0)
                                return r;
                }

                if (key_str) {
                        r = sd_json_variant_append_arrayb(
                                        &opts_inner,
                                        SD_JSON_BUILD_ARRAY(
                                                SD_JSON_BUILD_STRING("key"),
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
                                                SD_JSON_BUILD_STRING("dst_port"),
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
                                                SD_JSON_BUILD_STRING("tos"),
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
                                                SD_JSON_BUILD_STRING("ttl"),
                                                SD_JSON_BUILD_STRING(ttl_str)));
                        if (r < 0)
                                return r;
                }

                if (t->dont_fragment >= 0) {
                        r = sd_json_variant_append_arrayb(
                                        &opts_inner,
                                        SD_JSON_BUILD_ARRAY(
                                                SD_JSON_BUILD_STRING("df_default"),
                                                SD_JSON_BUILD_STRING(t->dont_fragment > 0 ? "true" : "false")));
                        if (r < 0)
                                return r;
                }

                r = sd_json_build(
                                &options,
                                SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_STRING("map"),
                                        SD_JSON_BUILD_VARIANT(opts_inner)));
                if (r < 0)
                        return r;
        }

        if (tunnel_exists) {
                /* UPDATE existing Interface options and external_ids */
                struct ovs_name_check iface_check = { .name = netdev->ifname };
                ovsdb_monitor_foreach(mon, "Interface", ovs_check_name_cb, &iface_check);

                log_netdev_debug(netdev, "OVS tunnel '%s' already exists, updating", strna(netdev->ifname));

                if (iface_check.found) {
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *update_iface = NULL;
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *update_where = NULL;
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *update_op = NULL;

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

                if (tunnel_port_uuid) {
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *port_update_row = NULL;
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *port_update_where = NULL;
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *port_update_op = NULL;

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
                                        SD_JSON_BUILD_STRING("name"),
                                        SD_JSON_BUILD_STRING("=="),
                                        SD_JSON_BUILD_STRING(t->bridge))));
        if (r < 0)
                return r;

        r = sd_json_build(
                        &mutations,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_STRING("ports"),
                                        SD_JSON_BUILD_STRING("insert"),
                                        SD_JSON_BUILD_ARRAY(
                                                SD_JSON_BUILD_STRING("set"),
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
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *external_ids = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *iface_row = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *iface_op = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *iface_ref = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *port_row = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *port_op = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *port_ref = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *where = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *mutations = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *mutate_op = NULL;
        _cleanup_free_ char *iface_uuid_name = NULL;
        _cleanup_free_ char *port_uuid_name = NULL;
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
                struct ovs_name_check check = { .name = network->ovs_bridge_name };
                ovsdb_monitor_foreach(mon, "Bridge", ovs_check_name_cb, &check);
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
                struct ovs_name_check check = { .name = ifname };
                ovsdb_monitor_foreach(mon, "Port", ovs_check_name_cb, &check);
                if (check.found) {
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *update_row = NULL;
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *update_where = NULL;
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *update_op = NULL;
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *update_ext = NULL;

                        log_debug("OVS port '%s' (from .network) already exists, updating", ifname);

                        r = ovs_build_external_ids(network->filename, &update_ext);
                        if (r < 0)
                                return r;

                        /* Always emit optional columns so removed config resets the OVSDB column */
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *tag_v = NULL;
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *vlan_mode_v = NULL;

                        r = ovs_build_optional_int(network->ovs_port_tag, network->ovs_port_tag != VLANID_INVALID, &tag_v);
                        if (r < 0)
                                return r;
                        r = ovs_build_optional_string(network->ovs_port_vlan_mode, &vlan_mode_v);
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
                        SD_JSON_BUILD_PAIR_CONDITION(!!network->ovs_port_vlan_mode, "vlan_mode", SD_JSON_BUILD_STRING(network->ovs_port_vlan_mode)),
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
                                        SD_JSON_BUILD_STRING("name"),
                                        SD_JSON_BUILD_STRING("=="),
                                        SD_JSON_BUILD_STRING(network->ovs_bridge_name))));
        if (r < 0)
                return r;

        r = sd_json_build(
                        &mutations,
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_STRING("ports"),
                                        SD_JSON_BUILD_STRING("insert"),
                                        SD_JSON_BUILD_ARRAY(
                                                SD_JSON_BUILD_STRING("set"),
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
                if (r < 0)
                        log_warning_errno(r, "Failed to attach '%s' to OVS bridge: %m", link->ifname);
        }

        return 0;
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
         * reconcile after reconnect will rebuild whatever state was lost. */
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
                                                struct ovs_name_check check = { .name = netdev->ifname };
                                                if (mon)
                                                        ovsdb_monitor_foreach(mon, "Port", ovs_check_name_cb, &check);
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
        if (m->ovs_pending_teardown && m->ovs_inflight_transacts == 0) {
                log_debug("OVS pending teardown: drained, releasing client");
                m->ovs_pending_teardown = false;
                m->ovs_reconnect_timer = sd_event_source_disable_unref(m->ovs_reconnect_timer);
                m->ovs_reconnect_delay = 0;
                m->ovsdb = ovsdb_client_unref(m->ovsdb);
                m->ovs_reconcile_pending = false;
        }

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
         * everything: the database state is unknown, the manager may be tearing
         * down, and the next reconnect will re-attempt the clear via the marker
         * file. result==NULL covers both NULL/NULL (unref cancel) and NULL with
         * synthetic_error="connection failed" (FAILED-state cancel). */
        if (!result) {
                log_debug("OVS clear transact aborted (cancel/disconnect), skipping post-processing");
                return 0;
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
                return 0;
        }

        /* Validate per-op results: each op should be an object without an "error" key.
         * Don't mark the clear as successful if any op failed. */
        if (!sd_json_variant_is_array(result)) {
                log_warning("OVS clear returned unexpected (non-array) result, not setting marker");
                return 0;
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
                        return 0;
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
        OVSDBMonitor *mon = ovsdb_client_get_monitor(client);
        if (mon && ovsdb_monitor_count(mon, "Bridge") == 0) {
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

        return 0;
}

int ovs_clear_database(Manager *m) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *ops = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *where_all = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *update_row = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *update_op = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *comment_op = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *empty_set = NULL;
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
                                SD_JSON_BUILD_STRING("set"),
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
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *ops = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *comment_op = NULL;
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

        /* Phase 2: ports */
        HASHMAP_FOREACH(netdev, m->netdevs) {
                if (netdev->kind != NETDEV_KIND_OVS_PORT)
                        continue;

                r = ovs_reconcile_port(m, netdev, &ops);
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
