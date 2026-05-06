/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "networkd-forward.h"

#if ENABLE_OPENVSWITCH

/* Perform OVS reconciliation: scan all loaded OVS netdevs, build
 * OVSDB transact operations, and send them to ovsdb-server.
 * Creates missing objects (INSERT) and updates existing ones (UPDATE). */
int ovs_reconcile(Manager *m);

/* Clear all OVSDB state (ClearDatabaseOnBoot= support).
 * Empties the bridges set on the root Open_vSwitch row;
 * OVSDB garbage-collects the orphaned rows. Reconciliation
 * runs automatically from the clear completion callback. */
int ovs_clear_database(Manager *m);

/* Look up the OVS Bridge row's fail_mode by bridge name.
 * Returns NULL if not found or not set. The returned pointer aliases
 * the monitor cache — copy if retained beyond the next OVSDB update. */
const char* ovs_monitor_get_bridge_fail_mode(Manager *m, const char *bridge_name);

/* Look up the OVS Bridge row's ports (Port UUIDs resolved to names).
 * Returns a strv that caller owns, or NULL if not found. */
int ovs_monitor_get_bridge_ports(Manager *m, const char *bridge_name, char ***ret_ports);

#endif
