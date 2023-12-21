/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-event.h"

#include "json.h"
#include "time-util.h"
#include "varlink-idl.h"

/* A minimal Varlink implementation. We only implement the minimal, obvious bits here though. No validation,
 * no introspection, no name service, just the stuff actually needed.
 *
 * You might wonder why we aren't using libvarlink here? Varlink is a very simple protocol, which allows us
 * to write our own implementation relatively easily. However, the main reasons are these:
 *
 * • We want to use our own JSON subsystem, with all the benefits that brings (i.e. accurate unsigned+signed
 *   64-bit integers, full fuzzing, logging during parsing and so on). If we'd want to use that with
 *   libvarlink we'd have to serialize and deserialize all the time from its own representation which is
 *   inefficient and nasty.
 *
 * • We want integration into sd-event, but also synchronous event-loop-less operation
 *
 * • We need proper per-UID accounting and access control, since we want to allow communication between
 *   unprivileged clients and privileged servers.
 *
 * • And of course, we don't want the name service and introspection stuff for now (though that might
 *   change).
 */

typedef struct Varlink Varlink;
typedef struct VarlinkServer VarlinkServer;

typedef enum VarlinkReplyFlags {
        VARLINK_REPLY_ERROR     = 1 << 0,
        VARLINK_REPLY_CONTINUES = 1 << 1,
        VARLINK_REPLY_LOCAL     = 1 << 2,
} VarlinkReplyFlags;

typedef enum VarlinkMethodFlags {
        VARLINK_METHOD_ONEWAY = 1 << 0,
        VARLINK_METHOD_MORE   = 2 << 1,
} VarlinkMethodFlags;

typedef enum VarlinkServerFlags {
        VARLINK_SERVER_ROOT_ONLY        = 1 << 0, /* Only accessible by root */
        VARLINK_SERVER_MYSELF_ONLY      = 1 << 1, /* Only accessible by our own UID */
        VARLINK_SERVER_ACCOUNT_UID      = 1 << 2, /* Do per user accounting */
        VARLINK_SERVER_INHERIT_USERDATA = 1 << 3, /* Initialize Varlink connection userdata from VarlinkServer userdata */
        _VARLINK_SERVER_FLAGS_ALL = (1 << 4) - 1,
} VarlinkServerFlags;

typedef int (*VarlinkMethod)(Varlink *link, JsonVariant *parameters, VarlinkMethodFlags flags, void *userdata);
typedef int (*VarlinkReply)(Varlink *link, JsonVariant *parameters, const char *error_id, VarlinkReplyFlags flags, void *userdata);
typedef int (*VarlinkConnect)(VarlinkServer *server, Varlink *link, void *userdata);
typedef void (*VarlinkDisconnect)(VarlinkServer *server, Varlink *link, void *userdata);

int varlink_connect_address(Varlink **ret, const char *address);
int varlink_connect_exec(Varlink **ret, const char *command, char **argv);
int varlink_connect_url(Varlink **ret, const char *url);
int varlink_connect_fd(Varlink **ret, int fd);

Varlink* varlink_ref(Varlink *link);
Varlink* varlink_unref(Varlink *v);

int varlink_get_fd(Varlink *v);
int varlink_get_events(Varlink *v);
int varlink_get_timeout(Varlink *v, usec_t *ret);

int varlink_attach_event(Varlink *v, sd_event *e, int64_t priority);
void varlink_detach_event(Varlink *v);
sd_event *varlink_get_event(Varlink *v);

int varlink_process(Varlink *v);
int varlink_wait(Varlink *v, usec_t timeout);

int varlink_is_idle(Varlink *v);

int varlink_flush(Varlink *v);
int varlink_close(Varlink *v);

Varlink* varlink_flush_close_unref(Varlink *v);
Varlink* varlink_close_unref(Varlink *v);

/* Enqueue method call, not expecting a reply */
int varlink_send(Varlink *v, const char *method, JsonVariant *parameters);
int varlink_sendb(Varlink *v, const char *method, ...);

/* Send method call and wait for reply */
int varlink_call(Varlink *v, const char *method, JsonVariant *parameters, JsonVariant **ret_parameters, const char **ret_error_id, VarlinkReplyFlags *ret_flags);
int varlink_callb(Varlink *v, const char *method, JsonVariant **ret_parameters, const char **ret_error_id, VarlinkReplyFlags *ret_flags, ...);

/* Send method call and begin collecting all 'more' replies into an array, finishing when a final reply is sent */
int varlink_collect(Varlink *v, const char *method, JsonVariant *parameters, JsonVariant **ret_parameters, const char **ret_error_id, VarlinkReplyFlags *ret_flags);
int varlink_collectb(Varlink *v, const char *method, JsonVariant **ret_parameters, const char **ret_error_id, VarlinkReplyFlags *ret_flags, ...);

/* Enqueue method call, expect a reply, which is eventually delivered to the reply callback */
int varlink_invoke(Varlink *v, const char *method, JsonVariant *parameters);
int varlink_invokeb(Varlink *v, const char *method, ...);

/* Enqueue method call, expect a reply now, and possibly more later, which are all delivered to the reply callback */
int varlink_observe(Varlink *v, const char *method, JsonVariant *parameters);
int varlink_observeb(Varlink *v, const char *method, ...);

/* Enqueue a final reply */
int varlink_reply(Varlink *v, JsonVariant *parameters);
int varlink_replyb(Varlink *v, ...);

/* Enqueue a (final) error */
int varlink_error(Varlink *v, const char *error_id, JsonVariant *parameters);
int varlink_errorb(Varlink *v, const char *error_id, ...);
int varlink_error_invalid_parameter(Varlink *v, JsonVariant *parameters);
int varlink_error_invalid_parameter_name(Varlink *v, const char *name);
int varlink_error_errno(Varlink *v, int error);

/* Enqueue a "more" reply */
int varlink_notify(Varlink *v, JsonVariant *parameters);
int varlink_notifyb(Varlink *v, ...);

/* Parsing incoming data via json_dispatch() and generate a nice error on parse errors */
int varlink_dispatch(Varlink *v, JsonVariant *parameters, const JsonDispatch table[], void *userdata);

/* Write outgoing fds into the socket (to be associated with the next enqueued message) */
int varlink_push_fd(Varlink *v, int fd);
int varlink_dup_fd(Varlink *v, int fd);
int varlink_reset_fds(Varlink *v);

/* Read incoming fds from the socket (associated with the currently handled message) */
int varlink_peek_fd(Varlink *v, size_t i);
int varlink_take_fd(Varlink *v, size_t i);

int varlink_set_allow_fd_passing_input(Varlink *v, bool b);
int varlink_set_allow_fd_passing_output(Varlink *v, bool b);

/* Bind a disconnect, reply or timeout callback */
int varlink_bind_reply(Varlink *v, VarlinkReply reply);

void* varlink_set_userdata(Varlink *v, void *userdata);
void* varlink_get_userdata(Varlink *v);

int varlink_get_peer_uid(Varlink *v, uid_t *ret);
int varlink_get_peer_pid(Varlink *v, pid_t *ret);

int varlink_set_relative_timeout(Varlink *v, usec_t usec);

VarlinkServer* varlink_get_server(Varlink *v);

int varlink_set_description(Varlink *v, const char *d);

/* Create a varlink server */
int varlink_server_new(VarlinkServer **ret, VarlinkServerFlags flags);
VarlinkServer *varlink_server_ref(VarlinkServer *s);
VarlinkServer *varlink_server_unref(VarlinkServer *s);

/* Add addresses or fds to listen on */
int varlink_server_listen_address(VarlinkServer *s, const char *address, mode_t mode);
int varlink_server_listen_fd(VarlinkServer *s, int fd);
int varlink_server_listen_auto(VarlinkServer *s);
int varlink_server_add_connection(VarlinkServer *s, int fd, Varlink **ret);

/* Bind callbacks */
int varlink_server_bind_method(VarlinkServer *s, const char *method, VarlinkMethod callback);
int varlink_server_bind_method_many_internal(VarlinkServer *s, ...);
#define varlink_server_bind_method_many(s, ...) varlink_server_bind_method_many_internal(s, __VA_ARGS__, NULL)
int varlink_server_bind_connect(VarlinkServer *s, VarlinkConnect connect);
int varlink_server_bind_disconnect(VarlinkServer *s, VarlinkDisconnect disconnect);

/* Add interface definition */
int varlink_server_add_interface(VarlinkServer *s, const VarlinkInterface *interface);
int varlink_server_add_interface_many_internal(VarlinkServer *s, ...);
#define varlink_server_add_interface_many(s, ...) varlink_server_add_interface_many_internal(s, __VA_ARGS__, NULL)

void* varlink_server_set_userdata(VarlinkServer *s, void *userdata);
void* varlink_server_get_userdata(VarlinkServer *s);

int varlink_server_attach_event(VarlinkServer *v, sd_event *e, int64_t priority);
int varlink_server_detach_event(VarlinkServer *v);
sd_event *varlink_server_get_event(VarlinkServer *v);

int varlink_server_loop_auto(VarlinkServer *server);

int varlink_server_shutdown(VarlinkServer *server);

int varlink_server_set_exit_on_idle(VarlinkServer *s, bool b);

unsigned varlink_server_connections_max(VarlinkServer *s);
unsigned varlink_server_connections_per_uid_max(VarlinkServer *s);

int varlink_server_set_connections_per_uid_max(VarlinkServer *s, unsigned m);
int varlink_server_set_connections_max(VarlinkServer *s, unsigned m);

unsigned varlink_server_current_connections(VarlinkServer *s);

int varlink_server_set_description(VarlinkServer *s, const char *description);

typedef enum VarlinkInvocationFlags {
        VARLINK_ALLOW_LISTEN                     = 1 << 0,
        VARLINK_ALLOW_ACCEPT                     = 1 << 1,
        _VARLINK_SERVER_INVOCATION_FLAGS_MAX     = (1 << 2) - 1,
        _VARLINK_SERVER_INVOCATION_FLAGS_INVALID = -EINVAL,
} VarlinkInvocationFlags;

int varlink_invocation(VarlinkInvocationFlags flags);

DEFINE_TRIVIAL_CLEANUP_FUNC(Varlink *, varlink_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(Varlink *, varlink_close_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(Varlink *, varlink_flush_close_unref);
DEFINE_TRIVIAL_CLEANUP_FUNC(VarlinkServer *, varlink_server_unref);

/* These are local errors that never cross the wire, and are our own invention */
#define VARLINK_ERROR_DISCONNECTED "io.systemd.Disconnected"
#define VARLINK_ERROR_TIMEOUT "io.systemd.TimedOut"
#define VARLINK_ERROR_PROTOCOL "io.systemd.Protocol"

/* This one we invented, and use for generically propagating system errors (errno) to clients */
#define VARLINK_ERROR_SYSTEM "io.systemd.System"

/* These are errors defined in the Varlink spec */
#define VARLINK_ERROR_INTERFACE_NOT_FOUND "org.varlink.service.InterfaceNotFound"
#define VARLINK_ERROR_METHOD_NOT_FOUND "org.varlink.service.MethodNotFound"
#define VARLINK_ERROR_METHOD_NOT_IMPLEMENTED "org.varlink.service.MethodNotImplemented"
#define VARLINK_ERROR_INVALID_PARAMETER "org.varlink.service.InvalidParameter"
#define VARLINK_ERROR_PERMISSION_DENIED "org.varlink.service.PermissionDenied"
#define VARLINK_ERROR_EXPECTED_MORE "org.varlink.service.ExpectedMore"
