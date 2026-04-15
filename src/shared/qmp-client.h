/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

typedef int (*qmp_event_callback_t)(
                QmpClient *client,
                const char *event,
                sd_json_variant *data,
                void *userdata);

typedef void (*qmp_disconnect_callback_t)(
                QmpClient *client,
                void *userdata);

/* Success: (result, NULL, 0). QMP error: (NULL, desc, -EIO). Transport: (NULL, NULL, -errno). */
typedef int (*qmp_command_callback_t)(
                QmpClient *client,
                sd_json_variant *result,
                const char *error_desc,
                int error,
                void *userdata);

/* Bundles arguments + fds for one command. Construct fresh per invoke via the macros below. */
typedef struct QmpClientArgs {
        sd_json_variant *arguments;
        int *fds_consume;
        size_t n_fds;
} QmpClientArgs;

#define QMP_CLIENT_ARGS(args_) \
        (&(QmpClientArgs){ .arguments = (args_) })
#define QMP_CLIENT_ARGS_FD(args_, fd_) \
        (&(QmpClientArgs){ .arguments = (args_), .fds_consume = (int[]){ (fd_) }, .n_fds = 1 })

/* Takes ownership of fd; handshake runs lazily on first invoke or from the event loop. */
int qmp_client_connect_fd(QmpClient **ret, int fd);

int qmp_client_attach_event(QmpClient *c, sd_event *event, int64_t priority);

/* Single non-blocking pump step: write → dispatch → parse → read → disconnect. Returns >0 if
 * progress was made, 0 if idle, <0 on error (-ENOTCONN on disconnect). Same contract as
 * sd_varlink_process(). */
int qmp_client_process(QmpClient *c);

/* Block on the transport fd until readable, or until timeout (USEC_INFINITY for no timeout).
 * Same contract as sd_varlink_wait(). */
int qmp_client_wait(QmpClient *c, uint64_t timeout_usec);

/* True iff there are no outstanding command replies (slots set is empty). Useful as the pump-loop
 * exit condition for callers driving the client synchronously via process() + wait(). */
bool qmp_client_is_idle(QmpClient *c);

/* True iff the connection is dead. Stable terminal state — once set, it stays set. */
bool qmp_client_is_disconnected(QmpClient *c);

/* True iff the handshake has completed and the client is ready to forward commands. */
bool qmp_client_is_running(QmpClient *c);

/* Async send. Returns 0 on send (callback will fire later), negative errno on failure. */
int qmp_client_invoke(
                QmpClient *client,
                const char *command,
                QmpClientArgs *args,
                qmp_command_callback_t callback,
                void *userdata);

/* Allocate and reserve an internal id for a command that the caller will build themselves.
 * Used by consumers that need to construct the full command variant outside the client and
 * have the response correlate back through qmp_client_invoke_raw(). */
uint64_t qmp_client_reserve_id(QmpClient *client);

/* Async send of a pre-built command. The cmd variant must already contain "execute" (or
 * "exec-oob") and "id": <id> fields — the id is the value previously obtained from
 * qmp_client_reserve_id(). Same return contract as qmp_client_invoke(). */
int qmp_client_invoke_raw(
                QmpClient *client,
                sd_json_variant *cmd,
                uint64_t id,
                QmpClientArgs *args,
                qmp_command_callback_t callback,
                void *userdata);

void qmp_client_bind_event(QmpClient *c, qmp_event_callback_t callback, void *userdata);
void qmp_client_bind_disconnect(QmpClient *c, qmp_disconnect_callback_t callback, void *userdata);
int qmp_client_set_description(QmpClient *c, const char *description);
sd_event* qmp_client_get_event(QmpClient *c);
unsigned qmp_client_next_fdset_id(QmpClient *client);

QmpClient* qmp_client_unref(QmpClient *p);

DEFINE_TRIVIAL_CLEANUP_FUNC(QmpClient *, qmp_client_unref);

/* Borrowed pointer to the QMP greeting variant received from QEMU during handshake, or
 * NULL if not yet received. Consumers that need to replay the greeting (e.g. when
 * wrapping additional clients over the same underlying connection) can use this to
 * reproduce exactly what QEMU sent without synthesising one. */
sd_json_variant* qmp_client_get_greeting(QmpClient *client);

/* Returns true iff any object entry in schema (result of query-qmp-schema) has a member with this
 * name. QEMU's introspection replaces type names with opaque numeric ids, so lookup-by-type-name is
 * impossible — but member names are real. Use only when the member name is unique in the schema. */
bool qmp_schema_has_member(sd_json_variant *schema, const char *member_name);
