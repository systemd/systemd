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

void* qmp_client_set_userdata(QmpClient *c, void *userdata);
void* qmp_client_get_userdata(QmpClient *c);

/* Async send. Returns 0 on send (callback will fire later), negative errno on failure. If
 * ret_slot is non-NULL, returns a reference to a QmpSlot which can be used to cancel the call
 * (by unreffing it before the reply arrives). */
int qmp_client_invoke(
                QmpClient *client,
                QmpSlot **ret_slot,
                const char *command,
                QmpClientArgs *args,
                qmp_command_callback_t callback,
                void *userdata);

/* Synchronous send + receive. Pumps the event loop until the reply arrives. On success
 * *ret_result is a fresh reference (caller unrefs) and *ret_error_desc is a freshly allocated
 * string (caller frees) — multiple concurrent calls on the same client therefore don't
 * invalidate each other's outputs. */
int qmp_client_call(
                QmpClient *client,
                const char *command,
                QmpClientArgs *args,
                sd_json_variant **ret_result,
                char **ret_error_desc);

/* Issue a QMP command asynchronously and return an sd_future that resolves when the reply
 * arrives. sd_future_result(f) is 0 once a reply has landed (success or QMP-level error;
 * use future_get_qmp_reply() to retrieve the result/error_desc), or a negative errno on
 * transport failure or cancellation. */
int qmp_client_call_future(
                QmpClient *client,
                const char *command,
                QmpClientArgs *args,
                sd_future **ret);

/* Extract the reply from a resolved qmp_client_call_future(). On success *ret_result is a fresh
 * reference (caller unrefs) and *ret_error_desc is a freshly allocated string (caller frees). */
int future_get_qmp_reply(
                sd_future *f,
                sd_json_variant **ret_result,
                char **ret_error_desc);

/* Fiber-suspending variant of qmp_client_call(): only valid on a fiber whose event loop matches
 * the client's. Same ownership contract as qmp_client_call(): on success *ret_result is a fresh
 * reference (caller unrefs) and *ret_error_desc is a freshly allocated string (caller frees). */
int qmp_client_call_suspend(
                QmpClient *client,
                const char *command,
                QmpClientArgs *args,
                sd_json_variant **ret_result,
                char **ret_error_desc);

void qmp_client_bind_event(QmpClient *c, qmp_event_callback_t callback, void *userdata);
void qmp_client_bind_disconnect(QmpClient *c, qmp_disconnect_callback_t callback, void *userdata);
int qmp_client_set_description(QmpClient *c, const char *description);
sd_event* qmp_client_get_event(QmpClient *c);
uint64_t qmp_client_next_fdset_id(QmpClient *client);

DECLARE_TRIVIAL_REF_UNREF_FUNC(QmpClient, qmp_client);
DEFINE_TRIVIAL_CLEANUP_FUNC(QmpClient *, qmp_client_unref);

DECLARE_TRIVIAL_REF_UNREF_FUNC(QmpSlot, qmp_slot);
DEFINE_TRIVIAL_CLEANUP_FUNC(QmpSlot *, qmp_slot_unref);

QmpClient* qmp_slot_get_client(QmpSlot *slot);

/* Returns true iff any object entry in schema (result of query-qmp-schema) has a member with this
 * name. QEMU's introspection replaces type names with opaque numeric ids, so lookup-by-type-name is
 * impossible — but member names are real. Use only when the member name is unique in the schema. */
bool qmp_schema_has_member(sd_json_variant *schema, const char *member_name);
