/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

typedef struct QmpClient QmpClient;

typedef int (*qmp_event_callback_t)(
                QmpClient *client,
                const char *event,
                sd_json_variant *data,
                void *userdata);

typedef void (*qmp_disconnect_callback_t)(
                QmpClient *client,
                void *userdata);

/* Fires once after the handshake; enqueue probes via QMP_CLIENT_ARGS_PROBE. */
typedef int (*qmp_client_probe_callback_t)(
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
        const int *fds;
        size_t n_fds;
        bool is_probe;  /* handshake-time probe; requires PROBING state */
} QmpClientArgs;

#define QMP_CLIENT_ARGS(args_) \
        (&(QmpClientArgs){ .arguments = (args_) })
#define QMP_CLIENT_ARGS_FD(args_, fd_) \
        (&(QmpClientArgs){ .arguments = (args_), .fds = (int[]){ (fd_) }, .n_fds = 1 })
#define QMP_CLIENT_ARGS_PROBE(args_) \
        (&(QmpClientArgs){ .arguments = (args_), .is_probe = true })

/* Takes ownership of fd; handshake runs lazily on first invoke or from the event loop. */
int qmp_client_connect_fd(QmpClient **ret, int fd);

int qmp_client_attach_event(QmpClient *c, sd_event *event, int64_t priority);

/* Async send. Returns 0 on send (callback will fire later), negative errno on failure. */
int qmp_client_invoke(
                QmpClient *client,
                const char *command,
                QmpClientArgs *args,
                qmp_command_callback_t callback,
                void *userdata);

void qmp_client_bind_event(QmpClient *c, qmp_event_callback_t callback);
void qmp_client_bind_disconnect(QmpClient *c, qmp_disconnect_callback_t callback);
/* Must be called before qmp_client_attach_event(). */
void qmp_client_bind_probe(QmpClient *c, qmp_client_probe_callback_t callback, void *userdata);
void* qmp_client_set_userdata(QmpClient *c, void *userdata);
int qmp_client_set_description(QmpClient *c, const char *description);
sd_event* qmp_client_get_event(QmpClient *c);
unsigned qmp_client_next_fdset_id(QmpClient *client);

QmpClient* qmp_client_unref(QmpClient *p);

DEFINE_TRIVIAL_CLEANUP_FUNC(QmpClient *, qmp_client_unref);

/* Returns true iff any object entry in schema (result of query-qmp-schema) has a member with this
 * name. QEMU's introspection replaces type names with opaque numeric ids, so lookup-by-type-name is
 * impossible — but member names are real. Use only when the member name is unique in the schema. */
bool qmp_schema_has_member(sd_json_variant *schema, const char *member_name);
