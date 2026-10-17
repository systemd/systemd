/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "log.h"
#include "path-util.h"
#include "pidref.h"
#include "recurse-dir.h"
#include "set.h"
#include "socket-util.h"
#include "string-util.h"
#include "varlink-internal.h"
#include "varlink-util.h"
#include "version.h"

int varlink_get_peer_pidref(sd_varlink *v, PidRef *ret) {
        int r;

        assert_return(v, -EINVAL);
        assert_return(ret, -EINVAL);

        /* Returns r > 0 if we acquired the pidref via SO_PEERPIDFD (i.e. if we can use it for
         * authentication). Returns == 0 if we didn't, and the pidref should not be used for
         * authentication. */

        int pidfd = sd_varlink_get_peer_pidfd(v);
        if (pidfd < 0) {
                if (!ERRNO_IS_NEG_IOCTL_NOT_SUPPORTED(pidfd))
                        return pidfd;

                pid_t pid;
                r = sd_varlink_get_peer_pid(v, &pid);
                if (r < 0)
                        return r;

                r = pidref_set_pid(ret, pid);
                if (r < 0)
                        return r;

                return 0; /* didn't get pidfd securely */
        }

        r = pidref_set_pidfd(ret, pidfd);
        if (r < 0)
                return r;

        return 1; /* got pidfd securely */
}

int varlink_call_and_log(
                sd_varlink *v,
                const char *method,
                sd_json_variant *parameters,
                sd_json_variant **ret_parameters) {

        sd_json_variant *reply = NULL;
        const char *error_id = NULL;
        int r;

        assert_return(v, -EINVAL);
        assert_return(method, -EINVAL);

        r = sd_varlink_call(v, method, parameters, &reply, &error_id);
        if (r < 0)
                return log_error_errno(r, "Failed to issue %s() varlink call: %m", method);
        if (error_id) {
                r = sd_varlink_error_to_errno(error_id, reply); /* If this is a system errno style error, output it with %m */
                if (r != -EBADR)
                        return log_error_errno(r, "Failed to issue %s() varlink call: %m", method);

                return log_error_errno(r, "Failed to issue %s() varlink call: %s", method, error_id);
        }

        if (ret_parameters)
                *ret_parameters = TAKE_PTR(reply);

        return 0;
}

int varlink_callb_and_log(
                sd_varlink *v,
                const char *method,
                sd_json_variant **ret_parameters,
                ...) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *parameters = NULL;
        va_list ap;
        int r;

        assert_return(v, -EINVAL);
        assert_return(method, -EINVAL);

        va_start(ap, ret_parameters);
        r = sd_json_buildv(&parameters, ap);
        va_end(ap);
        if (r < 0)
                return log_error_errno(r, "Failed to build JSON message: %m");

        return varlink_call_and_log(v, method, parameters, ret_parameters);
}

int varlink_many_notify(Set *s, sd_json_variant *parameters) {
        sd_varlink *link;
        int r = 1;

        if (set_isempty(s))
                return 0;

        SET_FOREACH(link, s)
                RET_GATHER(r, sd_varlink_notify(link, parameters));

        return r;
}

int varlink_many_notifyb(Set *s, ...) {
        int r;

        /* Equivalent to varlink_notifyb(), but does this for each entry of the supplied set of Varlink connections */

        if (set_isempty(s))
                return 0;

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *parameters = NULL;
        va_list ap;
        va_start(ap, s);
        r = sd_json_buildv(&parameters, ap);
        va_end(ap);
        if (r < 0)
                return r;

        return varlink_many_notify(s, parameters);
}

int varlink_many_reply(Set *s, sd_json_variant *parameters) {
        if (set_isempty(s))
                return 0;

        int r = 1;
        sd_varlink *link;
        SET_FOREACH(link, s)
                RET_GATHER(r, sd_varlink_reply(link, parameters));

        return r;
}

int varlink_many_error(Set *s, const char *error_id, sd_json_variant *parameters) {
        if (set_isempty(s))
                return 0;

        int r = 1;
        sd_varlink *link;
        SET_FOREACH(link, s)
                RET_GATHER(r, sd_varlink_error(link, error_id, parameters));

        return r;
}

int varlink_set_info_systemd(sd_varlink_server *server) {
        _cleanup_free_ char *product = NULL;

        product = strjoin("systemd (", program_invocation_short_name, ")");
        if (!product)
                return -ENOMEM;

        return sd_varlink_server_set_info(
                        server,
                        "The systemd Project",
                        product,
                        PROJECT_VERSION_FULL " (" GIT_VERSION ")",
                        "https://systemd.io/");
}

int varlink_server_new(
                sd_varlink_server **ret,
                sd_varlink_server_flags_t flags,
                void *userdata) {

        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *s = NULL;
        int r;

        assert(ret);

        r = sd_varlink_server_new(&s, flags|SD_VARLINK_SERVER_FD_PASSING_INPUT_STRICT);
        if (r < 0)
                return log_debug_errno(r, "Failed to allocate varlink server object: %m");

        r = varlink_set_info_systemd(s);
        if (r < 0)
                return log_debug_errno(r, "Failed to configure varlink server object: %m");

        sd_varlink_server_set_userdata(s, userdata);

        *ret = TAKE_PTR(s);
        return 0;
}

int varlink_check_privileged_peer(sd_varlink *vl) {
        int r;

        assert(vl);

        uid_t uid;
        r = sd_varlink_get_peer_uid(vl, &uid);
        if (r < 0)
                return log_debug_errno(r, "Failed to get peer UID: %m");

        if (uid != 0)
                return sd_varlink_error(vl, SD_VARLINK_ERROR_PERMISSION_DENIED, /* parameters= */ NULL);

        return 0;
}

DEFINE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
                varlink_hash_ops,
                void,
                trivial_hash_func,
                trivial_compare_func,
                sd_varlink,
                sd_varlink_unref);

#define VARLINK_EXECUTE_SOCKETS_MAX 255

typedef struct ExecuteDirectoryOperation {
        Set *links;
        sd_event_source *exit_event;
        sd_varlink_reply_t reply_cb;
        varlink_execute_directory_finished_t done_cb;
        void *userdata;
} ExecuteDirectoryOperation;

static ExecuteDirectoryOperation* execute_directory_operation_free(ExecuteDirectoryOperation *operation) {
        if (!operation)
                return NULL;

        operation->links = set_free(operation->links);
        operation->exit_event = sd_event_source_disable_unref(operation->exit_event);
        return mfree(operation);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(ExecuteDirectoryOperation*, execute_directory_operation_free);

static int execute_directory_operation_reply(
                sd_varlink *link,
                sd_json_variant *parameters,
                const char *error_id,
                sd_varlink_reply_flags_t flags,
                void *userdata) {

        ExecuteDirectoryOperation *op = ASSERT_PTR(userdata);
        int r;

        if (op->reply_cb) {
                r = op->reply_cb(link, parameters, error_id, flags, op->userdata);
                if (r < 0)
                        log_debug_errno(r, "Reply callback returned error, ignoring: %m");
        }

        if (!FLAGS_SET(flags, SD_VARLINK_REPLY_CONTINUES)) {
                assert_se(set_remove(op->links, link) == link);
                link = sd_varlink_close_unref(link);
        }

        if (set_isempty(op->links)) {
                if (op->done_cb) {
                        r = op->done_cb(op->userdata);
                        if (r < 0)
                                log_debug_errno(r, "Done callback returned error, ignoring: %m");
                }
                op = execute_directory_operation_free(op);
        }

        return 0;
}

static int execute_directory_operation_exit(sd_event_source *s, void *userdata) {
        ExecuteDirectoryOperation *op = ASSERT_PTR(userdata);
        execute_directory_operation_free(op);
        return 0;
}

static int varlink_execute_directory_internal(
                sd_event **event,
                const char *path,
                const char *method,
                sd_json_variant *parameters,
                bool more,
                usec_t timeout_usec,
                sd_varlink_reply_t reply,
                varlink_execute_directory_finished_t done,
                void *userdata) {

        int r;

        assert(event);
        assert(path);
        assert(method);

        /* Invokes the specified method on all Varlink sockets in the specified directory. Any reply
         * will be dispatched to the reply callback. Calls the done callback once the last reply has come in.
         *
         * Returns how many sockets were contacted. Note that done is NOT called if no replies ever came in.
         *
         * Usecase for all of this: hook directories, where components can link their sockets into to get
         * notified about certain system events. */

        _cleanup_close_ int fd = open(path, O_RDONLY|O_CLOEXEC|O_DIRECTORY);
        if (fd < 0)
                return log_debug_errno(errno, "Failed to open '%s': %m", path);

        _cleanup_free_ DirectoryEntries *dentries = NULL;
        r = readdir_all(fd, RECURSE_DIR_IGNORE_DOT|RECURSE_DIR_MUST_BE_SOCKET|RECURSE_DIR_MUST_BE_SYMLINK, &dentries);
        if (r < 0)
                return log_debug_errno(r, "Failed to enumerate '%s': %m", path);

        _cleanup_(execute_directory_operation_freep) ExecuteDirectoryOperation *op = NULL;
        op = new(ExecuteDirectoryOperation, 1);
        if (!op)
                return log_oom_debug();
        *op = (ExecuteDirectoryOperation) {
                .reply_cb = reply,
                .done_cb = done,
                .userdata = userdata,
        };

        size_t t = 0;
        FOREACH_ARRAY(dp, dentries->entries, dentries->n_entries) {
                struct dirent *de = *dp;

                t++;

                _cleanup_free_ char *j = path_join(path, de->d_name);
                if (!j)
                        return log_oom_debug();

                if (set_size(op->links) >= VARLINK_EXECUTE_SOCKETS_MAX) {
                        log_debug("Too many sockets (%zu) in directory, skipping '%s'.", t, j);
                        continue;
                }

                _cleanup_close_ int socket_fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
                if (socket_fd < 0)
                        return log_debug_errno(errno, "Failed to allocate AF_UNIX/SOCK_STREAM socket: %m");

                r = connect_unix_path(socket_fd, fd, de->d_name);
                if (r < 0) {
                        log_debug_errno(r, "Failed to connect to '%s', ignoring: %m", j);
                        continue;
                }

                if (!*event) {
                        r = sd_event_new(event);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to allocate event loop: %m");
                }

                _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
                r = sd_varlink_connect_fd(&link, socket_fd);
                if (r < 0)
                        return log_debug_errno(r, "Failed to allocate Varlink connection: %m");

                TAKE_FD(socket_fd);

                r = sd_varlink_attach_event(link, *event, /* priority= */ 0);
                if (r < 0)
                        return log_debug_errno(r, "Failed to attach varlink connection to event loop: %m");

                sd_varlink_set_userdata(link, op);

                r = sd_varlink_bind_reply(link, execute_directory_operation_reply);
                if (r < 0)
                        return log_debug_errno(r, "Failed to bind reply callback: %m");

                r = sd_varlink_set_description(link, j);
                if (r < 0)
                        return log_debug_errno(r, "Failed to set description: %m");

                r = sd_varlink_set_relative_timeout(link, timeout_usec);
                if (r < 0)
                        return log_debug_errno(r, "Failed to set relative timeout: %m");

                if (more)
                        r = sd_varlink_observe(link, method, parameters);
                else
                        r = sd_varlink_invoke(link, method, parameters);
                if (r < 0)
                        return log_debug_errno(r, "Failed to enqueue message on Varlink connection: %m");

                if (set_ensure_consume(&op->links, &varlink_hash_ops, TAKE_PTR(link)) < 0)
                        return log_oom_debug();
        }

        size_t count = set_size(op->links);
        if (count == 0)
                return 0;

        /* We're going to return and get called back later by the event loop. But something else might
         * terminate the event loop before we're done. So, let's make sure we catch that and clean up */
        r = sd_event_add_exit(*event, &op->exit_event, execute_directory_operation_exit, op);
        if (r < 0)
                return r;

        TAKE_PTR(op); /* We'll be called back via either _reply or _exit */

        assert(count < INT_MAX); /* Because there are at most VARLINK_EXECUTE_SOCKETS_MAX */
        return (int) count;
}

int varlink_execute_directory_async(
                sd_event *event,
                const char *path,
                const char *method,
                sd_json_variant *parameters,
                bool more,
                usec_t timeout_usec,
                sd_varlink_reply_t reply,
                varlink_execute_directory_finished_t done,
                void *userdata) {

        assert(event);
        return varlink_execute_directory_internal(&event, path, method, parameters, more, timeout_usec,
                                                  reply, done, userdata);
}

typedef struct ExecuteDirectoryContext {
        sd_event *event;
        sd_varlink_reply_t reply_cb;
        void *userdata;
} ExecuteDirectoryContext;

static void execute_directory_context_done(ExecuteDirectoryContext *context) {
        sd_event_unref(context->event);
}

static int execute_directory_sync_reply(
                sd_varlink *link,
                sd_json_variant *parameters,
                const char *error_id,
                sd_varlink_reply_flags_t flags,
                void *userdata) {

        ExecuteDirectoryContext *context = ASSERT_PTR(userdata);
        assert(context->reply_cb);
        return context->reply_cb(link, parameters, error_id, flags, context->userdata);
}

static int execute_directory_sync_done(void *userdata) {
        ExecuteDirectoryContext *context = ASSERT_PTR(userdata);
        if (context->event)
                return sd_event_exit(context->event, 0);
        return 0;
}

int varlink_execute_directory(
                const char *path,
                const char *method,
                sd_json_variant *parameters,
                bool more,
                usec_t timeout_usec,
                sd_varlink_reply_t reply,
                void *userdata) {

        int r;

        /* Like varlink_execute_directory_async, but blocks until the last reply comes in. */

        _cleanup_(execute_directory_context_done) ExecuteDirectoryContext ctx = {};
        if (reply) {
                ctx.reply_cb = reply;
                ctx.userdata = userdata;
                reply = execute_directory_sync_reply;
        }
        int count = varlink_execute_directory_internal(&ctx.event, path, method, parameters, more,
                                                       timeout_usec, reply, execute_directory_sync_done, &ctx);
        if (count <= 0)
                return count;

        assert(ctx.event);

        r = sd_event_loop(ctx.event);
        if (r < 0)
                return log_debug_errno(r, "Failed to run event loop: %m");

        return count;
}
