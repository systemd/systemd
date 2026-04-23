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

/* Async send. Returns 0 on send (callback will fire later), negative errno on failure. */
int qmp_client_invoke(
                QmpClient *client,
                const char *command,
                QmpClientArgs *args,
                qmp_command_callback_t callback,
                void *userdata);

/* Synchronous send + receive. Pumps the event loop until the reply arrives. *ret_result and
 * *ret_error_desc are borrowed pointers into the last reply, valid until the next
 * qmp_client_call(). Same contract as sd_varlink_call(). */
int qmp_client_call(
                QmpClient *client,
                const char *command,
                QmpClientArgs *args,
                sd_json_variant **ret_result,
                const char **ret_error_desc);

void qmp_client_bind_event(QmpClient *c, qmp_event_callback_t callback, void *userdata);
void qmp_client_bind_disconnect(QmpClient *c, qmp_disconnect_callback_t callback, void *userdata);
int qmp_client_set_description(QmpClient *c, const char *description);
sd_event* qmp_client_get_event(QmpClient *c);
unsigned qmp_client_next_fdset_id(QmpClient *client);

QmpClient* qmp_client_unref(QmpClient *p);

DEFINE_TRIVIAL_CLEANUP_FUNC(QmpClient *, qmp_client_unref);

/* Returns true iff any object entry in schema (result of query-qmp-schema) has a member with this
 * name. QEMU's introspection replaces type names with opaque numeric ids, so lookup-by-type-name is
 * impossible — but member names are real. Use only when the member name is unique in the schema. */
bool qmp_schema_has_member(sd_json_variant *schema, const char *member_name);
