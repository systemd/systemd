/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "cleanup-util.h"
#include "shared-forward.h"

typedef struct QmpClient QmpClient;

typedef void (*qmp_event_callback_t)(
                QmpClient *client,
                const char *event,
                sd_json_variant *data,
                void *userdata);

typedef void (*qmp_disconnect_callback_t)(
                QmpClient *client,
                void *userdata);

/* Callback for async command completion. On success: result is non-NULL, error_class is NULL, error is 0.
 * On QMP error: result is NULL, error_class is the QMP error class string, error is -EIO.
 * On transport failure: result and error_class are NULL, error is a negative errno. */
typedef void (*qmp_command_callback_t)(
                QmpClient *client,
                sd_json_variant *result,
                const char *error_class,
                int error,
                void *userdata);

/* Connect to QMP via a pre-created socketpair fd. Takes ownership of fd (closes it on error or when
 * the QmpClient is freed). Performs a blocking handshake: reads greeting, sends qmp_capabilities, waits
 * for success. The fd remains in blocking mode for subsequent qmp_client_call() invocations; call
 * qmp_client_start_async() to switch to non-blocking event-driven operation. */
int qmp_client_connect_fd(QmpClient **ret, int fd, sd_event *event);

/* Switch from blocking setup phase to async event processing. Must be called
 * after all blocking setup (qmp_client_call, drive config, cont). */
int qmp_client_start_async(QmpClient *client);

/* Execute a QMP command synchronously (blocking). Only valid before qmp_client_start_async().
 * Returns 0 on success (result in ret_result), -EIO on QMP error (class in reterr_error),
 * negative errno on transport failure. ret_result and reterr_error may be NULL. */
int qmp_client_call(
                QmpClient *client,
                const char *command,
                sd_json_variant *arguments,
                sd_json_variant **ret_result,
                char **reterr_error);

/* Like qmp_client_call(), but sends an FD as SCM_RIGHTS ancillary data alongside
 * the command message. Used for the QEMU "getfd" command. */
int qmp_client_call_send_fd(
                QmpClient *client,
                const char *command,
                sd_json_variant *arguments,
                int fd,
                sd_json_variant **ret_result,
                char **reterr_error);

/* Represents a QEMU fdset created via add-fd. The path field ("/dev/fdset/N")
 * is used in blockdev-add filename fields. Multiple fds can be added to the
 * same fdset (for different O_ACCMODE flags to support reopen). */
typedef struct QmpFdset {
        unsigned id;
        char *path;   /* owned: "/dev/fdset/N" */
} QmpFdset;

static inline void qmp_fdset_done(QmpFdset *fdset) {
        assert(fdset);
        fdset->path = mfree(fdset->path);
}

/* Create a new fdset and add an fd to it via add-fd + SCM_RIGHTS. */
int qmp_client_fdset_new(QmpClient *client, int fd, QmpFdset *ret);

/* Add another fd to an existing fdset (for multi-access-mode support). */
int qmp_client_fdset_add_fd(QmpClient *client, QmpFdset *fdset, int fd);

/* Wait for a QMP job to conclude by watching JOB_STATUS_CHANGE events on the blocking
 * socket. After the job concludes, queries its error status via query-jobs and dismisses it.
 * Only valid during the blocking phase (before qmp_client_start_async).
 * Returns 0 on success, -EIO on job error (message in reterr_error), negative errno on
 * transport failure. */
int qmp_client_job_wait(QmpClient *client, const char *job_id, char **reterr_error);

/* Send a QMP command asynchronously. The callback is invoked exactly once from the sd-event loop when
 * the matching response arrives or the connection drops (-ECONNRESET). Returns 0 if the command was
 * sent and registered (callback will be invoked later), negative errno on failure (callback NOT invoked). */
int qmp_client_execute(
                QmpClient *client,
                const char *command,
                sd_json_variant *arguments,
                qmp_command_callback_t callback,
                void *userdata);
void qmp_client_set_event_callback(QmpClient *client, qmp_event_callback_t callback, void *userdata);
void qmp_client_set_disconnect_callback(QmpClient *client, qmp_disconnect_callback_t callback, void *userdata);
sd_event *qmp_client_get_event(QmpClient *client);
QmpClient *qmp_client_free(QmpClient *client);

DEFINE_TRIVIAL_CLEANUP_FUNC(QmpClient *, qmp_client_free);
