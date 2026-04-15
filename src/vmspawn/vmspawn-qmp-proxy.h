/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"
#include "vmspawn-qmp.h"

/* AcquireQMP proxy: terminates each upgraded varlink connection and multiplexes it
 * onto the bridge's shared QmpClient.
 *
 * Multiple acquirers may be active concurrently, alongside vmspawn's own internal QMP
 * traffic. QMP uses the "id" field for request/response correlation; different
 * acquirers will reuse the same id values and may collide with vmspawn's internal
 * counter. The proxy solves this by rewriting ids on outbound commands (fresh id
 * reserved from the shared QmpClient) and reversing the remap on matching responses
 * so each acquirer sees its own id namespace.
 *
 * Events are fanned out to every acquirer that has completed its own
 * qmp_capabilities negotiation — mirroring QEMU's native behaviour of suppressing
 * events during cap-negotiation mode. */

/* Handle the varlink-side AcquireQMP method. The handler has already verified that the
 * caller requested the upgrade; this function performs the actual
 * sd_varlink_reply_and_upgrade, adopts the returned fd pair, replays QEMU's greeting,
 * and wires the new AcquiredQmp into the bridge. Returns 0 on success, in which case
 * the caller must not touch `link` further (it's been closed by the upgrade). */
int vmspawn_qmp_proxy_acquire(VmspawnQmpBridge *bridge, sd_varlink *link);

/* Forward a QEMU event to every acquirer that has completed cap-negotiation. `raw` is
 * the full event variant (preferred; includes the timestamp) or NULL for synthetic
 * events (e.g. the SHUTDOWN emitted when the QMP transport dies), in which case the
 * broadcaster reconstructs a minimal `{"event":...,"data":...}` variant from `event`
 * and `data`. */
void vmspawn_qmp_proxy_broadcast_event(
                VmspawnQmpBridge *bridge,
                sd_json_variant *raw,
                const char *event,
                sd_json_variant *data);

/* Tear down every acquirer attached to the bridge. Invoked from the QMP disconnect
 * callback (so pending slot callbacks see a NULL weak back-pointer) and from the
 * varlink context free path. */
void vmspawn_qmp_proxy_drain(VmspawnQmpBridge *bridge);
