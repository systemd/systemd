/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <poll.h>
#include <stdlib.h>
#include <unistd.h>

#include "sd-daemon.h"
#include "sd-event.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "env-util.h"
#include "errno-list.h"
#include "errno-util.h"
#include "escape.h"
#include "extract-word.h"
#include "fd-util.h"
#include "format-util.h"
#include "glyph-util.h"
#include "hashmap.h"
#include "io-util.h"
#include "iovec-util.h"
#include "json-util.h"
#include "list.h"
#include "log.h"
#include "mkdir.h"
#include "path-util.h"
#include "pidfd-util.h"
#include "pidref.h"
#include "process-util.h"
#include "socket-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "umask-util.h"
#include "user-util.h"
#include "varlink-idl-util.h"
#include "varlink-internal.h"
#include "varlink-io.systemd.h"
#include "varlink-org.varlink.service.h"

#define VARLINK_DEFAULT_CONNECTIONS_MAX 4096U
#define VARLINK_DEFAULT_CONNECTIONS_PER_UID_MAX 1024U

#define VARLINK_DEFAULT_TIMEOUT_USEC (45U*USEC_PER_SEC)
#define VARLINK_BUFFER_MAX (16U*1024U*1024U)
#define VARLINK_READ_SIZE (64U*1024U)
#define VARLINK_COLLECT_MAX 1024U
#define VARLINK_QUEUE_MAX (64U*1024U)

static const char* const varlink_state_table[_VARLINK_STATE_MAX] = {
        [VARLINK_IDLE_CLIENT]              = "idle-client",
        [VARLINK_AWAITING_REPLY]           = "awaiting-reply",
        [VARLINK_AWAITING_REPLY_MORE]      = "awaiting-reply-more",
        [VARLINK_CALLING]                  = "calling",
        [VARLINK_CALLED]                   = "called",
        [VARLINK_COLLECTING]               = "collecting",
        [VARLINK_COLLECTING_REPLY]         = "collecting-reply",
        [VARLINK_PROCESSING_REPLY]         = "processing-reply",
        [VARLINK_IDLE_SERVER]              = "idle-server",
        [VARLINK_PROCESSING_METHOD]        = "processing-method",
        [VARLINK_PROCESSING_METHOD_MORE]   = "processing-method-more",
        [VARLINK_PROCESSING_METHOD_ONEWAY] = "processing-method-oneway",
        [VARLINK_PROCESSED_METHOD]         = "processed-method",
        [VARLINK_PENDING_METHOD]           = "pending-method",
        [VARLINK_PENDING_METHOD_MORE]      = "pending-method-more",
        [VARLINK_PENDING_DISCONNECT]       = "pending-disconnect",
        [VARLINK_PENDING_TIMEOUT]          = "pending-timeout",
        [VARLINK_PROCESSING_DISCONNECT]    = "processing-disconnect",
        [VARLINK_PROCESSING_TIMEOUT]       = "processing-timeout",
        [VARLINK_PROCESSING_FAILURE]       = "processing-failure",
        [VARLINK_DISCONNECTED]             = "disconnected",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(varlink_state, VarlinkState);

static int varlink_format_queue(sd_varlink *v);
static void varlink_server_test_exit_on_idle(sd_varlink_server *s);

static VarlinkJsonQueueItem* varlink_json_queue_item_free(VarlinkJsonQueueItem *q) {
        if (!q)
                return NULL;

        sd_json_variant_unref(q->data);
        close_many(q->fds, q->n_fds);

        return mfree(q);
}

static VarlinkJsonQueueItem* varlink_json_queue_item_new(sd_json_variant *m, const int fds[], size_t n_fds) {
        VarlinkJsonQueueItem *q;

        assert(m);
        assert(fds || n_fds == 0);

        q = malloc(offsetof(VarlinkJsonQueueItem, fds) + sizeof(int) * n_fds);
        if (!q)
                return NULL;

        *q = (VarlinkJsonQueueItem) {
                .data = sd_json_variant_ref(m),
                .n_fds = n_fds,
        };

        memcpy_safe(q->fds, fds, n_fds * sizeof(int));

        return TAKE_PTR(q);
}

static void varlink_set_state(sd_varlink *v, VarlinkState state) {
        assert(v);
        assert(state >= 0 && state < _VARLINK_STATE_MAX);

        if (v->state < 0)
                varlink_log(v, "Setting state %s",
                            varlink_state_to_string(state));
        else
                varlink_log(v, "Changing state %s %s %s",
                            varlink_state_to_string(v->state),
                            glyph(GLYPH_ARROW_RIGHT),
                            varlink_state_to_string(state));

        v->state = state;
}

static int varlink_new(sd_varlink **ret) {
        sd_varlink *v;

        assert(ret);

        v = new(sd_varlink, 1);
        if (!v)
                return -ENOMEM;

        *v = (sd_varlink) {
                .n_ref = 1,
                .input_fd = -EBADF,
                .output_fd = -EBADF,

                .state = _VARLINK_STATE_INVALID,

                .ucred = UCRED_INVALID,

                .peer_pidfd = -EBADF,

                .timestamp = USEC_INFINITY,
                .timeout = VARLINK_DEFAULT_TIMEOUT_USEC,

                .allow_fd_passing_input = -1,

                .af = -1,

                .exec_pidref = PIDREF_NULL,
        };

        *ret = v;
        return 0;
}

_public_ int sd_varlink_connect_address(sd_varlink **ret, const char *address) {
        _cleanup_(sd_varlink_unrefp) sd_varlink *v = NULL;
        union sockaddr_union sockaddr;
        int r;

        assert_return(ret, -EINVAL);
        assert_return(address, -EINVAL);

        r = varlink_new(&v);
        if (r < 0)
                return log_debug_errno(r, "Failed to create varlink object: %m");

        v->input_fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (v->input_fd < 0)
                return log_debug_errno(errno, "Failed to create AF_UNIX socket: %m");

        v->output_fd = v->input_fd = fd_move_above_stdio(v->input_fd);
        v->af = AF_UNIX;

        r = sockaddr_un_set_path(&sockaddr.un, address);
        if (r < 0) {
                if (r != -ENAMETOOLONG)
                        return log_debug_errno(r, "Failed to set socket address '%s': %m", address);

                /* This is a file system path, and too long to fit into sockaddr_un. Let's connect via O_PATH
                 * to this socket. */

                r = connect_unix_path(v->input_fd, AT_FDCWD, address);
        } else
                r = RET_NERRNO(connect(v->input_fd, &sockaddr.sa, r));

        if (r < 0) {
                if (!IN_SET(r, -EAGAIN, -EINPROGRESS))
                        return log_debug_errno(r, "Failed to connect to %s: %m", address);

                v->connecting = true; /* We are asynchronously connecting, i.e. the connect() is being
                                       * processed in the background. As long as that's the case the socket
                                       * is in a special state: it's there, we can poll it for EPOLLOUT, but
                                       * if we attempt to write() to it before we see EPOLLOUT we'll get
                                       * ENOTCONN (and not EAGAIN, like we would for a normal connected
                                       * socket that isn't writable at the moment). Since ENOTCONN on write()
                                       * hence can mean two different things (i.e. connection not complete
                                       * yet vs. already disconnected again), we store as a boolean whether
                                       * we are still in connect(). */
        }

        varlink_set_state(v, VARLINK_IDLE_CLIENT);

        *ret = TAKE_PTR(v);
        return 0;
}

_public_ int sd_varlink_connect_exec(sd_varlink **ret, const char *_command, char **_argv) {
        _cleanup_close_pair_ int pair[2] = EBADF_PAIR;
        _cleanup_(pidref_done_sigkill_wait) PidRef pidref = PIDREF_NULL;
        _cleanup_free_ char *command = NULL;
        _cleanup_strv_free_ char **argv = NULL;
        int r;

        assert_return(ret, -EINVAL);
        assert_return(_command, -EINVAL);

        /* Copy the strings, in case they point into our own argv[], which we'll invalidate shortly because
         * we rename the child process */
        command = strdup(_command);
        if (!command)
                return -ENOMEM;

        if (strv_isempty(_argv))
                argv = strv_new(command);
        else
                argv = strv_copy(_argv);
        if (!argv)
                return -ENOMEM;

        log_debug("Forking off Varlink child process '%s'.", command);

        if (socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0, pair) < 0)
                return log_debug_errno(errno, "Failed to allocate AF_UNIX socket pair: %m");

        r = fd_nonblock(pair[1], false);
        if (r < 0)
                return log_debug_errno(r, "Failed to disable O_NONBLOCK for varlink socket: %m");

        r = pidref_safe_fork_full(
                        "(sd-vlexec)",
                        /* stdio_fds= */ NULL,
                        /* except_fds= */ (int[]) { pair[1] },
                        /* n_except_fds= */ 1,
                        FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_REOPEN_LOG|FORK_LOG|FORK_RLIMIT_NOFILE_SAFE,
                        &pidref);
        if (r < 0)
                return log_debug_errno(r, "Failed to spawn process: %m");
        if (r == 0) {
                char spid[DECIMAL_STR_MAX(pid_t)+1];
                const char *setenv_list[] = {
                        "LISTEN_FDS", "1",
                        "LISTEN_PID", spid,
                        "LISTEN_FDNAMES", "varlink",
                        NULL, NULL,
                };
                /* Child */

                pair[0] = -EBADF;

                r = move_fd(pair[1], 3, /* cloexec= */ false);
                if (r < 0) {
                        log_debug_errno(r, "Failed to move file descriptor to 3: %m");
                        _exit(EXIT_FAILURE);
                }

                xsprintf(spid, PID_FMT, pidref.pid);

                uint64_t pidfdid;
                if (pidfd_get_inode_id_self_cached(&pidfdid) >= 0) {
                        r = setenvf("LISTEN_PIDFDID", /* overwrite= */ true, "%" PRIu64, pidfdid);
                        if (r < 0) {
                                log_debug_errno(r, "Failed to set environment variable 'LISTEN_PIDFDID': %m");
                                _exit(EXIT_FAILURE);
                        }
                }

                STRV_FOREACH_PAIR(a, b, setenv_list) {
                        if (setenv(*a, *b, /* overwrite= */ true) < 0) {
                                log_debug_errno(errno, "Failed to set environment variable '%s': %m", *a);
                                _exit(EXIT_FAILURE);
                        }
                }

                execvp(command, argv);
                log_debug_errno(r, "Failed to invoke process '%s': %m", command);
                _exit(EXIT_FAILURE);
        }

        pair[1] = safe_close(pair[1]);

        sd_varlink *v;
        r = varlink_new(&v);
        if (r < 0)
                return log_debug_errno(r, "Failed to create varlink object: %m");

        v->output_fd = v->input_fd = TAKE_FD(pair[0]);
        v->af = AF_UNIX;
        v->exec_pidref = TAKE_PIDREF(pidref);
        varlink_set_state(v, VARLINK_IDLE_CLIENT);

        *ret = v;
        return 0;
}

static int ssh_path(const char **ret) {
        assert(ret);

        const char *ssh = secure_getenv("SYSTEMD_SSH") ?: "ssh";
        if (!path_is_valid(ssh))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "SSH path is not valid, refusing: %s", ssh);

        *ret = ssh;
        return 0;
}

static int varlink_connect_ssh_unix(sd_varlink **ret, const char *where) {
        _cleanup_close_pair_ int pair[2] = EBADF_PAIR;
        _cleanup_(pidref_done_sigkill_wait) PidRef pidref = PIDREF_NULL;
        int r;

        assert_return(ret, -EINVAL);
        assert_return(where, -EINVAL);

        /* Connects to an SSH server via OpenSSH 9.4's -W switch to connect to a remote AF_UNIX socket. For
         * now we do not expose this function directly, but only via varlink_connect_url(). */

        const char *ssh;
        r = ssh_path(&ssh);
        if (r < 0)
                return r;

        const char *e = strchr(where, ':');
        if (!e)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "SSH specification lacks a : separator between host and path, refusing: %s", where);

        _cleanup_free_ char *h = strndup(where, e - where);
        if (!h)
                return log_oom_debug();

        if (!path_is_absolute(e + 1))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Remote AF_UNIX socket path is not absolute, refusing: %s", e + 1);

        _cleanup_free_ char *p = NULL;
        r = path_simplify_alloc(e + 1, &p);
        if (r < 0)
                return r;

        if (!path_is_normalized(p))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Specified path is not normalized, refusing: %s", p);

        log_debug("Forking off SSH child process '%s -W %s %s'.", ssh, p, h);

        if (socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0, pair) < 0)
                return log_debug_errno(errno, "Failed to allocate AF_UNIX socket pair: %m");

        r = pidref_safe_fork_full(
                        "(sd-vlssh)",
                        /* stdio_fds= */ (int[]) { pair[1], pair[1], STDERR_FILENO },
                        /* except_fds= */ NULL,
                        /* n_except_fds= */ 0,
                        FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_REOPEN_LOG|FORK_LOG|FORK_RLIMIT_NOFILE_SAFE|FORK_REARRANGE_STDIO,
                        &pidref);
        if (r < 0)
                return log_debug_errno(r, "Failed to spawn process: %m");
        if (r == 0) {
                /* Child */

                execlp(ssh, "ssh", "-W", p, h, NULL);
                log_debug_errno(errno, "Failed to invoke %s: %m", ssh);
                _exit(EXIT_FAILURE);
        }

        pair[1] = safe_close(pair[1]);

        sd_varlink *v;
        r = varlink_new(&v);
        if (r < 0)
                return log_debug_errno(r, "Failed to create varlink object: %m");

        v->output_fd = v->input_fd = TAKE_FD(pair[0]);
        v->af = AF_UNIX;
        v->exec_pidref = TAKE_PIDREF(pidref);
        varlink_set_state(v, VARLINK_IDLE_CLIENT);

        *ret = v;
        return 0;
}

static int varlink_connect_ssh_exec(sd_varlink **ret, const char *where) {
        _cleanup_close_pair_ int input_pipe[2] = EBADF_PAIR, output_pipe[2] = EBADF_PAIR;
        _cleanup_(pidref_done_sigkill_wait) PidRef pidref = PIDREF_NULL;
        int r;

        assert_return(ret, -EINVAL);
        assert_return(where, -EINVAL);

        /* Connects to an SSH server to connect to a remote process' stdin/stdout. For now we do not expose
         * this function directly, but only via varlink_connect_url(). */

        const char *ssh;
        r = ssh_path(&ssh);
        if (r < 0)
                return r;

        const char *e = strchr(where, ':');
        if (!e)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "SSH specification lacks a : separator between host and path, refusing: %s", where);

        _cleanup_free_ char *h = strndup(where, e - where);
        if (!h)
                return log_oom_debug();

        _cleanup_strv_free_ char **cmdline = NULL;
        r = strv_split_full(&cmdline, e + 1, /* separators= */ NULL, EXTRACT_CUNESCAPE|EXTRACT_UNQUOTE);
        if (r < 0)
                return log_debug_errno(r, "Failed to split command line: %m");
        if (strv_isempty(cmdline))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Remote command line is empty, refusing.");

        _cleanup_strv_free_ char **full_cmdline = NULL;
        full_cmdline = strv_new("ssh", "-e", "none", "-T", h, "env", "SYSTEMD_VARLINK_LISTEN=-");
        if (!full_cmdline)
                return log_oom_debug();
        r = strv_extend_strv_consume(&full_cmdline, TAKE_PTR(cmdline), /* filter_duplicates= */ false);
        if (r < 0)
                return log_oom_debug();

        _cleanup_free_ char *j = NULL;
        j = quote_command_line(full_cmdline, SHELL_ESCAPE_EMPTY);
        if (!j)
                return log_oom_debug();

        log_debug("Forking off SSH child process: %s", j);

        if (pipe2(input_pipe, O_CLOEXEC) < 0)
                return log_debug_errno(errno, "Failed to allocate input pipe: %m");
        if (pipe2(output_pipe, O_CLOEXEC) < 0)
                return log_debug_errno(errno, "Failed to allocate output pipe: %m");

        r = pidref_safe_fork_full(
                        "(sd-vlssh)",
                        /* stdio_fds= */ (int[]) { input_pipe[0], output_pipe[1], STDERR_FILENO },
                        /* except_fds= */ NULL,
                        /* n_except_fds= */ 0,
                        FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_DEATHSIG_SIGTERM|FORK_REOPEN_LOG|FORK_LOG|FORK_RLIMIT_NOFILE_SAFE|FORK_REARRANGE_STDIO,
                        &pidref);
        if (r < 0)
                return log_debug_errno(r, "Failed to spawn process: %m");
        if (r == 0) {
                /* Child */
                execvp(ssh, full_cmdline);
                log_debug_errno(errno, "Failed to invoke %s: %m", j);
                _exit(EXIT_FAILURE);
        }

        input_pipe[0] = safe_close(input_pipe[0]);
        output_pipe[1] = safe_close(output_pipe[1]);

        r = fd_nonblock(input_pipe[1], true);
        if (r < 0)
                return log_debug_errno(r, "Failed to make input pipe non-blocking: %m");

        r = fd_nonblock(output_pipe[0], true);
        if (r < 0)
                return log_debug_errno(r, "Failed to make output pipe non-blocking: %m");

        sd_varlink *v;
        r = varlink_new(&v);
        if (r < 0)
                return log_debug_errno(r, "Failed to create varlink object: %m");

        v->input_fd = TAKE_FD(output_pipe[0]);
        v->output_fd = TAKE_FD(input_pipe[1]);
        v->af = AF_UNSPEC;
        v->exec_pidref = TAKE_PIDREF(pidref);
        varlink_set_state(v, VARLINK_IDLE_CLIENT);

        *ret = v;
        return 0;
}

/* Do basic validation of the URL scheme (loosely following RFC 1738) */
static bool is_valid_url_scheme(const char *s) {
        return !isempty(s) &&
                strchr(LOWERCASE_LETTERS, s[0]) &&
                in_charset(s, LOWERCASE_LETTERS DIGITS "+.-") &&
                filename_is_valid(s);
}

_public_ int sd_varlink_connect_url(sd_varlink **ret, const char *url) {
        _cleanup_free_ char *c = NULL;
        const char *p;
        enum {
                SCHEME_UNIX,
                SCHEME_EXEC,
                SCHEME_SSH_UNIX,
                SCHEME_SSH_EXEC,
        } scheme;
        int r;

        assert_return(ret, -EINVAL);
        assert_return(url, -EINVAL);

        // FIXME: Maybe add support for vsock: URL schemes here.

        /* The Varlink URL scheme is a bit underdefined. We support only the spec-defined unix: transport for
         * now, plus exec:, ssh: transports we made up ourselves. Strictly speaking this shouldn't even be
         * called "URL", since it has nothing to do with Internet URLs by RFC. */

        p = startswith(url, "unix:");
        if (p)
                scheme = SCHEME_UNIX;
        else if ((p = startswith(url, "exec:")))
                scheme = SCHEME_EXEC;
        else if ((p = STARTSWITH_SET(url, "ssh:", "ssh-unix:")))
                scheme = SCHEME_SSH_UNIX;
        else if ((p = startswith(url, "ssh-exec:")))
                scheme = SCHEME_SSH_EXEC;
        else {
                /* scheme is not built-in: check if we have a bridge helper binary */
                const char *colon = strchr(url, ':');
                if (!colon)
                        return log_debug_errno(SYNTHETIC_ERRNO(EPROTONOSUPPORT),
                                               "Invalid URL '%s': does not contain a ':'", url);

                _cleanup_free_ char *scheme_name = strndup(url, colon - url);
                if (!scheme_name)
                        return log_oom_debug();

                if (!is_valid_url_scheme(scheme_name))
                        return log_debug_errno(SYNTHETIC_ERRNO(EPROTONOSUPPORT),
                                               "URL scheme not valid as bridge name: %s", scheme_name);

                const char *bridges_dir = secure_getenv("SYSTEMD_VARLINK_BRIDGES_DIR") ?: VARLINK_BRIDGES_DIR;
                _cleanup_free_ char *bridge = path_join(bridges_dir, scheme_name);
                if (!bridge)
                        return log_oom_debug();

                if (access(bridge, X_OK) < 0) {
                        if (errno == ENOENT)
                                return log_debug_errno(SYNTHETIC_ERRNO(EPROTONOSUPPORT), "URL scheme '%s' not supported (and no auxiliary bridge binary is available).", scheme_name);

                        return log_debug_errno(errno, "Failed to look up varlink bridge binary '%s': %m", bridge);
                }

                return sd_varlink_connect_exec(ret, bridge, STRV_MAKE(bridge, url));
        }

        /* The varlink.org reference C library supports more than just file system paths. We might want to
         * support that one day too. For now simply refuse that for our built-in schemes. It is fine for
         * external scheme handled via plugins (see above). */
        if (p[strcspn(p, ";?#")] != '\0')
                return log_debug_errno(SYNTHETIC_ERRNO(EPROTONOSUPPORT), "URL parameterization with ';', '?', '#' not supported.");

        if (scheme == SCHEME_SSH_UNIX)
                return varlink_connect_ssh_unix(ret, p);
        if (scheme == SCHEME_SSH_EXEC)
                return varlink_connect_ssh_exec(ret, p);

        if (scheme == SCHEME_EXEC || p[0] != '@') { /* no path validity checks for abstract namespace sockets */

                if (!path_is_absolute(p))
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Specified path not absolute, refusing.");

                r = path_simplify_alloc(p, &c);
                if (r < 0)
                        return r;

                if (!path_is_normalized(c))
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Specified path is not normalized, refusing.");
        }

        if (scheme == SCHEME_EXEC)
                return sd_varlink_connect_exec(ret, c, NULL);

        return sd_varlink_connect_address(ret, c ?: p);
}

_public_ int sd_varlink_connect_fd_pair(sd_varlink **ret, int input_fd, int output_fd, const struct ucred *override_ucred) {
        sd_varlink *v;
        int r;

        assert_return(ret, -EINVAL);
        assert_return(input_fd >= 0, -EBADF);
        assert_return(output_fd >= 0, -EBADF);

        r = fd_nonblock(input_fd, true);
        if (r < 0)
                return log_debug_errno(r, "Failed to make input fd %d nonblocking: %m", input_fd);

        if (input_fd != output_fd) {
                r = fd_nonblock(output_fd, true);
                if (r < 0)
                        return log_debug_errno(r, "Failed to make output fd %d nonblocking: %m", output_fd);
        }

        r = varlink_new(&v);
        if (r < 0)
                return log_debug_errno(r, "Failed to create varlink object: %m");

        v->input_fd = input_fd;
        v->output_fd = output_fd;
        v->af = -1;

        if (override_ucred) {
                v->ucred = *override_ucred;
                v->ucred_acquired = true;
        }

        varlink_set_state(v, VARLINK_IDLE_CLIENT);

        /* Note that if this function is called we assume the passed socket (if it is one) is already
         * properly connected, i.e. any asynchronous connect() done on it already completed. Because of that
         * we'll not set the 'connecting' boolean here, i.e. we don't need to avoid write()ing to the socket
         * until the connection is fully set up. Behaviour here is hence a bit different from
         * varlink_connect_address() above, as there we do handle asynchronous connections ourselves and
         * avoid doing write() on it before we saw EPOLLOUT for the first time. */

        *ret = v;
        return 0;
}

_public_ int sd_varlink_connect_fd(sd_varlink **ret, int fd) {
        return sd_varlink_connect_fd_pair(ret, fd, fd, /* override_ucred= */ NULL);
}

static void varlink_detach_event_sources(sd_varlink *v) {
        assert(v);

        v->input_event_source = sd_event_source_disable_unref(v->input_event_source);
        v->output_event_source = sd_event_source_disable_unref(v->output_event_source);
        v->time_event_source = sd_event_source_disable_unref(v->time_event_source);
        v->quit_event_source = sd_event_source_disable_unref(v->quit_event_source);
        v->defer_event_source = sd_event_source_disable_unref(v->defer_event_source);
}

static void varlink_clear_current(sd_varlink *v) {
        assert(v);

        /* Clears the currently processed incoming message */
        v->current = sd_json_variant_unref(v->current);
        v->current_collected = sd_json_variant_unref(v->current_collected);
        v->current_method = NULL;
        v->current_reply_flags = 0;

        close_many(v->input_fds, v->n_input_fds);
        v->input_fds = mfree(v->input_fds);
        v->n_input_fds = 0;

        v->previous = varlink_json_queue_item_free(v->previous);
        if (v->sentinel != POINTER_MAX)
                v->sentinel = mfree(v->sentinel);
        else
                v->sentinel = NULL;
}

static void varlink_clear(sd_varlink *v) {
        assert(v);

        varlink_detach_event_sources(v);

        if (v->input_fd != v->output_fd) {
                v->input_fd = safe_close(v->input_fd);
                v->output_fd = safe_close(v->output_fd);
        } else
                v->output_fd = v->input_fd = safe_close(v->input_fd);

        varlink_clear_current(v);

        v->input_buffer = v->input_sensitive ? erase_and_free(v->input_buffer) : mfree(v->input_buffer);
        v->output_buffer = v->output_buffer_sensitive ? erase_and_free(v->output_buffer) : mfree(v->output_buffer);

        v->input_control_buffer = mfree(v->input_control_buffer);
        v->input_control_buffer_size = 0;

        close_many(v->output_fds, v->n_output_fds);
        v->output_fds = mfree(v->output_fds);
        v->n_output_fds = 0;

        close_many(v->pushed_fds, v->n_pushed_fds);
        v->pushed_fds = mfree(v->pushed_fds);
        v->n_pushed_fds = 0;

        LIST_CLEAR(queue, v->output_queue, varlink_json_queue_item_free);
        v->output_queue_tail = NULL;
        v->n_output_queue = 0;

        v->event = sd_event_unref(v->event);

        pidref_done_sigterm_wait(&v->exec_pidref);

        v->peer_pidfd = safe_close(v->peer_pidfd);
}

static sd_varlink* varlink_destroy(sd_varlink *v) {
        if (!v)
                return NULL;

        /* If this is called the server object must already been unreffed here. Why that? because when we
         * linked up the varlink connection with the server object we took one ref in each direction */
        assert(!v->server);

        varlink_clear(v);

        free(v->description);
        return mfree(v);
}

DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC(sd_varlink, sd_varlink, varlink_destroy);

static int varlink_test_disconnect(sd_varlink *v) {
        assert(v);

        /* Tests whether we the connection has been terminated. We are careful to not stop processing it
         * prematurely, since we want to handle half-open connections as well as possible and want to flush
         * out and read data before we close down if we can. */

        /* Already disconnected? */
        if (!VARLINK_STATE_IS_ALIVE(v->state))
                return 0;

        /* Wait until connection setup is complete, i.e. until asynchronous connect() completes */
        if (v->connecting)
                return 0;

        /* Still something to write and we can write? Stay around */
        if (v->output_buffer_size > 0 && !v->write_disconnected)
                return 0;

        /* Both sides gone already? Then there's no need to stick around */
        if (v->read_disconnected && v->write_disconnected)
                goto disconnect;

        /* If we are waiting for incoming data but the read side is shut down, disconnect. */
        if (IN_SET(v->state, VARLINK_AWAITING_REPLY, VARLINK_AWAITING_REPLY_MORE, VARLINK_CALLING, VARLINK_COLLECTING, VARLINK_IDLE_SERVER) && v->read_disconnected)
                goto disconnect;

        /* Similar, if are a client that hasn't written anything yet but the write side is dead, also
         * disconnect. We also explicitly check for POLLHUP here since we likely won't notice the write side
         * being down if we never wrote anything. */
        if (v->state == VARLINK_IDLE_CLIENT && (v->write_disconnected || v->got_pollhup))
                goto disconnect;

        /* We are on the server side and still want to send out more replies, but we saw POLLHUP already, and
         * either got no buffered bytes to write anymore or already saw a write error. In that case we should
         * shut down the varlink link. */
        if (IN_SET(v->state, VARLINK_PENDING_METHOD, VARLINK_PENDING_METHOD_MORE) && (v->write_disconnected || v->output_buffer_size == 0) && v->got_pollhup)
                goto disconnect;

        return 0;

disconnect:
        varlink_set_state(v, VARLINK_PENDING_DISCONNECT);
        return 1;
}

static int varlink_write(sd_varlink *v) {
        ssize_t n;
        int r;

        assert(v);

        if (!VARLINK_STATE_IS_ALIVE(v->state))
                return 0;
        if (v->connecting) /* Writing while we are still wait for a non-blocking connect() to complete will
                            * result in ENOTCONN, hence exit early here */
                return 0;
        if (v->write_disconnected)
                return 0;

        /* If needed let's convert some output queue json variants into text form */
        r = varlink_format_queue(v);
        if (r < 0)
                return r;

        if (v->output_buffer_size == 0)
                return 0;

        assert(v->output_fd >= 0);

        if (v->n_output_fds > 0) { /* If we shall send fds along, we must use sendmsg() */
                struct iovec iov = {
                        .iov_base = v->output_buffer + v->output_buffer_index,
                        .iov_len = v->output_buffer_size,
                };
                struct msghdr mh = {
                        .msg_iov = &iov,
                        .msg_iovlen = 1,
                        .msg_controllen = CMSG_SPACE(sizeof(int) * v->n_output_fds),
                };

                mh.msg_control = alloca0(mh.msg_controllen);

                struct cmsghdr *control = CMSG_FIRSTHDR(&mh);
                control->cmsg_len = CMSG_LEN(sizeof(int) * v->n_output_fds);
                control->cmsg_level = SOL_SOCKET;
                control->cmsg_type = SCM_RIGHTS;
                memcpy(CMSG_DATA(control), v->output_fds, sizeof(int) * v->n_output_fds);

                n = sendmsg(v->output_fd, &mh, MSG_DONTWAIT|MSG_NOSIGNAL);
        } else {
                /* We generally prefer recv()/send() (mostly because of MSG_NOSIGNAL) but also want to be compatible
                 * with non-socket IO, hence fall back automatically.
                 *
                 * Use a local variable to help gcc figure out that we set 'n' in all cases. */
                bool prefer_write = v->prefer_write;
                if (!prefer_write) {
                        n = send(v->output_fd, v->output_buffer + v->output_buffer_index, v->output_buffer_size, MSG_DONTWAIT|MSG_NOSIGNAL);
                        if (n < 0 && errno == ENOTSOCK)
                                prefer_write = v->prefer_write = true;
                }
                if (prefer_write)
                        n = write(v->output_fd, v->output_buffer + v->output_buffer_index, v->output_buffer_size);
        }
        if (n < 0) {
                if (errno == EAGAIN)
                        return 0;

                if (ERRNO_IS_DISCONNECT(errno)) {
                        /* If we get informed about a disconnect on write, then let's remember that, but not
                         * act on it just yet. Let's wait for read() to report the issue first. */
                        v->write_disconnected = true;
                        return 1;
                }

                return -errno;
        }

        if (v->output_buffer_sensitive)
                explicit_bzero_safe(v->output_buffer + v->output_buffer_index, n);

        v->output_buffer_size -= n;

        if (v->output_buffer_size == 0) {
                v->output_buffer_index = 0;
                v->output_buffer_sensitive = false; /* We can reset the sensitive flag once the buffer is empty */
        } else
                v->output_buffer_index += n;

        close_many(v->output_fds, v->n_output_fds);
        v->n_output_fds = 0;

        v->timestamp = now(CLOCK_MONOTONIC);
        return 1;
}

#define VARLINK_FDS_MAX (16U*1024U)

static int varlink_read(sd_varlink *v) {
        struct iovec iov;
        struct msghdr mh;
        size_t rs;
        ssize_t n;
        void *p;

        assert(v);

        if (!IN_SET(v->state, VARLINK_AWAITING_REPLY, VARLINK_AWAITING_REPLY_MORE, VARLINK_CALLING, VARLINK_COLLECTING, VARLINK_IDLE_SERVER))
                return 0;
        if (v->connecting) /* read() on a socket while we are in connect() will fail with EINVAL, hence exit early here */
                return 0;
        if (v->current)
                return 0;
        if (v->input_buffer_unscanned > 0)
                return 0;
        if (v->read_disconnected)
                return 0;

        if (v->input_buffer_size >= VARLINK_BUFFER_MAX)
                return -ENOBUFS;

        assert(v->input_fd >= 0);

        if (MALLOC_SIZEOF_SAFE(v->input_buffer) <= v->input_buffer_index + v->input_buffer_size) {
                size_t add;

                add = MIN(VARLINK_BUFFER_MAX - v->input_buffer_size, VARLINK_READ_SIZE);

                if (v->input_buffer_index == 0) {

                        if (!GREEDY_REALLOC(v->input_buffer, v->input_buffer_size + add))
                                return -ENOMEM;

                } else {
                        char *b;

                        b = new(char, v->input_buffer_size + add);
                        if (!b)
                                return -ENOMEM;

                        memcpy(b, v->input_buffer + v->input_buffer_index, v->input_buffer_size);

                        free_and_replace(v->input_buffer, b);
                        v->input_buffer_index = 0;
                }
        }

        p = v->input_buffer + v->input_buffer_index + v->input_buffer_size;
        rs = MALLOC_SIZEOF_SAFE(v->input_buffer) - (v->input_buffer_index + v->input_buffer_size);

        if (v->allow_fd_passing_input > 0) {
                iov = IOVEC_MAKE(p, rs);

                /* Allocate the fd buffer on the heap, since we need a lot of space potentially */
                if (!v->input_control_buffer) {
                        v->input_control_buffer_size = CMSG_SPACE(sizeof(int) * VARLINK_FDS_MAX);
                        v->input_control_buffer = malloc(v->input_control_buffer_size);
                        if (!v->input_control_buffer)
                                return -ENOMEM;
                }

                mh = (struct msghdr) {
                        .msg_iov = &iov,
                        .msg_iovlen = 1,
                        .msg_control = v->input_control_buffer,
                        .msg_controllen = v->input_control_buffer_size,
                };

                n = recvmsg_safe(v->input_fd, &mh, MSG_DONTWAIT|MSG_CMSG_CLOEXEC);
        } else {
                bool prefer_read = v->prefer_read;
                if (!prefer_read) {
                        n = recv(v->input_fd, p, rs, MSG_DONTWAIT);
                        if (n < 0)
                                n = -errno;
                        if (n == -ENOTSOCK)
                                prefer_read = v->prefer_read = true;
                }
                if (prefer_read) {
                        n = read(v->input_fd, p, rs);
                        if (n < 0)
                                n = -errno;
                }
        }
        if (ERRNO_IS_NEG_TRANSIENT(n))
                return 0;
        if (ERRNO_IS_NEG_DISCONNECT(n)) {
                v->read_disconnected = true;
                return 1;
        }
        if (n < 0)
                return n;
        if (n == 0) { /* EOF */

                if (v->allow_fd_passing_input > 0)
                        cmsg_close_all(&mh);

                v->read_disconnected = true;
                return 1;
        }

        if (v->allow_fd_passing_input > 0) {
                struct cmsghdr *cmsg;

                cmsg = cmsg_find(&mh, SOL_SOCKET, SCM_RIGHTS, (socklen_t) -1);
                if (cmsg) {
                        size_t add;

                        /* We only allow file descriptors to be passed along with the first byte of a
                         * message. If they are passed with any other byte this is a protocol violation. */
                        if (v->input_buffer_size != 0) {
                                cmsg_close_all(&mh);
                                return -EPROTO;
                        }

                        add = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
                        if (add > INT_MAX - v->n_input_fds) {
                                cmsg_close_all(&mh);
                                return -EBADF;
                        }

                        if (!GREEDY_REALLOC(v->input_fds, v->n_input_fds + add)) {
                                cmsg_close_all(&mh);
                                return -ENOMEM;
                        }

                        memcpy_safe(v->input_fds + v->n_input_fds, CMSG_TYPED_DATA(cmsg, int), add * sizeof(int));
                        v->n_input_fds += add;
                }
        }

        v->input_buffer_size += n;
        v->input_buffer_unscanned += n;

        return 1;
}

static int varlink_parse_message(sd_varlink *v) {
        const char *e;
        char *begin;
        size_t sz;
        int r;

        assert(v);

        if (v->current)
                return 0;
        if (v->input_buffer_unscanned <= 0)
                return 0;

        assert(v->input_buffer_unscanned <= v->input_buffer_size);
        assert(v->input_buffer_index + v->input_buffer_size <= MALLOC_SIZEOF_SAFE(v->input_buffer));

        begin = v->input_buffer + v->input_buffer_index;

        e = memchr(begin + v->input_buffer_size - v->input_buffer_unscanned, 0, v->input_buffer_unscanned);
        if (!e) {
                v->input_buffer_unscanned = 0;
                return 0;
        }

        sz = e - begin + 1;

        r = sd_json_parse(begin, 0, &v->current, NULL, NULL);
        if (v->input_sensitive)
                explicit_bzero_safe(begin, sz);
        if (r < 0) {
                /* If we encounter a parse failure flush all data. We cannot possibly recover from this,
                 * hence drop all buffered data now. */
                v->input_buffer_index = v->input_buffer_size = v->input_buffer_unscanned = 0;
                return varlink_log_errno(v, r, "Failed to parse JSON: %m");
        }

        if (v->input_sensitive) {
                /* Mark the parameters subfield as sensitive right-away, if that's requested */
                sd_json_variant *parameters = sd_json_variant_by_key(v->current, "parameters");
                if (parameters)
                        sd_json_variant_sensitive(parameters);
        }

        if (DEBUG_LOGGING) {
                _cleanup_(erase_and_freep) char *censored_text = NULL;

                /* Suppress sensitive fields in the debug output */
                r = sd_json_variant_format(v->current, /* flags= */ SD_JSON_FORMAT_CENSOR_SENSITIVE, &censored_text);
                if (r < 0)
                        return r;

                varlink_log(v, "Received message: %s", censored_text);
        }

        v->input_buffer_size -= sz;

        if (v->input_buffer_size == 0)
                v->input_buffer_index = 0;
        else
                v->input_buffer_index += sz;

        v->input_buffer_unscanned = v->input_buffer_size;
        return 1;
}

static int varlink_test_timeout(sd_varlink *v) {
        assert(v);

        if (!IN_SET(v->state, VARLINK_AWAITING_REPLY, VARLINK_AWAITING_REPLY_MORE, VARLINK_CALLING, VARLINK_COLLECTING))
                return 0;
        if (v->timeout == USEC_INFINITY)
                return 0;

        if (now(CLOCK_MONOTONIC) < usec_add(v->timestamp, v->timeout))
                return 0;

        varlink_set_state(v, VARLINK_PENDING_TIMEOUT);

        return 1;
}

static int varlink_dispatch_local_error(sd_varlink *v, const char *error) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *empty = NULL;
        int r;

        assert(v);
        assert(error);

        if (!v->reply_callback)
                return 0;

        r = sd_json_variant_new_object(&empty, NULL, 0);
        if (r < 0)
                return r;

        r = v->reply_callback(v, empty, error, SD_VARLINK_REPLY_ERROR|SD_VARLINK_REPLY_LOCAL, v->userdata);
        if (r < 0)
                varlink_log_errno(v, r, "Reply callback returned error, ignoring: %m");

        return 1;
}

static int varlink_dispatch_timeout(sd_varlink *v) {
        assert(v);

        if (v->state != VARLINK_PENDING_TIMEOUT)
                return 0;

        varlink_set_state(v, VARLINK_PROCESSING_TIMEOUT);
        varlink_dispatch_local_error(v, SD_VARLINK_ERROR_TIMEOUT);
        sd_varlink_close(v);

        return 1;
}

static int varlink_dispatch_disconnect(sd_varlink *v) {
        assert(v);

        if (v->state != VARLINK_PENDING_DISCONNECT)
                return 0;

        varlink_set_state(v, VARLINK_PROCESSING_DISCONNECT);
        varlink_dispatch_local_error(v, SD_VARLINK_ERROR_DISCONNECTED);
        sd_varlink_close(v);

        return 1;
}

static int varlink_sanitize_incoming_parameters(sd_json_variant **v) {
        int r;
        assert(v);

        /* Convert NULL or JSON null to empty object for method handlers (backward compatibility) */
        if (!*v || sd_json_variant_is_null(*v)) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *empty = NULL;
                r = sd_json_variant_new_object(&empty, NULL, 0);
                if (r < 0)
                        return r;
                /* sd_json_variant_unref() is a NOP if *v is NULL */
                sd_json_variant_unref(*v);
                *v = TAKE_PTR(empty);
                return 0;
        }

        /* Ensure we have an object */
        if (!sd_json_variant_is_object(*v))
                return -EINVAL;

        return 0;
}

static int varlink_dispatch_reply(sd_varlink *v) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *parameters = NULL;
        sd_varlink_reply_flags_t flags = 0;
        const char *error = NULL;
        sd_json_variant *e;
        const char *k;
        int r;

        assert(v);

        if (!IN_SET(v->state, VARLINK_AWAITING_REPLY, VARLINK_AWAITING_REPLY_MORE, VARLINK_CALLING, VARLINK_COLLECTING))
                return 0;
        if (!v->current)
                return 0;

        assert(v->n_pending > 0);

        if (!sd_json_variant_is_object(v->current))
                goto invalid;

        JSON_VARIANT_OBJECT_FOREACH(k, e, v->current) {

                if (streq(k, "error")) {
                        if (error)
                                goto invalid;
                        if (!sd_json_variant_is_string(e))
                                goto invalid;

                        error = sd_json_variant_string(e);
                        flags |= SD_VARLINK_REPLY_ERROR;

                } else if (streq(k, "parameters")) {
                        if (parameters)
                                goto invalid;
                        if (!sd_json_variant_is_object(e) && !sd_json_variant_is_null(e))
                                goto invalid;

                        parameters = sd_json_variant_ref(e);

                } else if (streq(k, "continues")) {
                        if (FLAGS_SET(flags, SD_VARLINK_REPLY_CONTINUES))
                                goto invalid;

                        if (!sd_json_variant_is_boolean(e))
                                goto invalid;

                        if (sd_json_variant_boolean(e))
                                flags |= SD_VARLINK_REPLY_CONTINUES;
                } else
                        goto invalid;
        }

        /* Replies with 'continue' set are only OK if we set 'more' when the method call was initiated */
        if (!IN_SET(v->state, VARLINK_AWAITING_REPLY_MORE, VARLINK_COLLECTING) && FLAGS_SET(flags, SD_VARLINK_REPLY_CONTINUES))
                goto invalid;

        /* An error is final */
        if (error && FLAGS_SET(flags, SD_VARLINK_REPLY_CONTINUES))
                goto invalid;

        r = varlink_sanitize_incoming_parameters(&parameters);
        if (r < 0)
                goto invalid;

        v->current_reply_flags = flags;

        if (IN_SET(v->state, VARLINK_AWAITING_REPLY, VARLINK_AWAITING_REPLY_MORE)) {
                varlink_set_state(v, VARLINK_PROCESSING_REPLY);

                if (v->reply_callback) {
                        r = v->reply_callback(v, parameters, error, flags, v->userdata);
                        if (r < 0)
                                varlink_log_errno(v, r, "Reply callback returned error, ignoring: %m");
                }

                varlink_clear_current(v);

                if (v->state == VARLINK_PROCESSING_REPLY) {
                        assert(v->n_pending > 0);

                        if (!FLAGS_SET(flags, SD_VARLINK_REPLY_CONTINUES))
                                v->n_pending--;

                        varlink_set_state(v,
                                          FLAGS_SET(flags, SD_VARLINK_REPLY_CONTINUES) ? VARLINK_AWAITING_REPLY_MORE :
                                          v->n_pending == 0 ? VARLINK_IDLE_CLIENT : VARLINK_AWAITING_REPLY);
                }
        } else if (v->state == VARLINK_COLLECTING)
                varlink_set_state(v, VARLINK_COLLECTING_REPLY);
        else {
                assert(v->state == VARLINK_CALLING);
                varlink_set_state(v, VARLINK_CALLED);
        }

        return 1;

invalid:
        varlink_set_state(v, VARLINK_PROCESSING_FAILURE);
        varlink_dispatch_local_error(v, SD_VARLINK_ERROR_PROTOCOL);
        sd_varlink_close(v);

        return 1;
}

static int generic_method_get_info(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        _cleanup_strv_free_ char **interfaces = NULL;
        int r;

        assert(link);
        assert(link->server);

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table= */ NULL, /* userdata= */ NULL);
        if (r != 0)
                return r;

        sd_varlink_interface *interface;
        HASHMAP_FOREACH(interface, link->server->interfaces) {
                r = strv_extend(&interfaces, interface->name);
                if (r < 0)
                        return r;
        }

        strv_sort(interfaces);

        return sd_varlink_replybo(
                        link,
                        SD_JSON_BUILD_PAIR_STRING("vendor", strempty(link->server->vendor)),
                        SD_JSON_BUILD_PAIR_STRING("product", strempty(link->server->product)),
                        SD_JSON_BUILD_PAIR_STRING("version", strempty(link->server->version)),
                        SD_JSON_BUILD_PAIR_STRING("url", strempty(link->server->url)),
                        SD_JSON_BUILD_PAIR_STRV("interfaces", interfaces));
}

static int generic_method_get_interface_description(
                sd_varlink *link,
                sd_json_variant *parameters,
                sd_varlink_method_flags_t flags,
                void *userdata) {

        static const sd_json_dispatch_field dispatch_table[] = {
                { "interface",  SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, 0, SD_JSON_MANDATORY },
                {}
        };
        _cleanup_free_ char *text = NULL;
        const sd_varlink_interface *interface;
        const char *name = NULL;
        int r;

        assert(link);

        r = sd_json_dispatch(parameters, dispatch_table, 0, &name);
        if (r < 0)
                return r;

        interface = hashmap_get(ASSERT_PTR(link->server)->interfaces, name);
        if (!interface)
                return sd_varlink_errorbo(
                                link,
                                SD_VARLINK_ERROR_INTERFACE_NOT_FOUND,
                                SD_JSON_BUILD_PAIR_STRING("interface", name));

        r = sd_varlink_idl_format(interface, &text);
        if (r < 0)
                return r;

        return sd_varlink_replybo(
                        link,
                        SD_JSON_BUILD_PAIR_STRING("description", text));
}

static int varlink_format_json(sd_varlink *v, sd_json_variant *m) {
        _cleanup_(erase_and_freep) char *text = NULL;
        int sz, r;

        assert(v);
        assert(m);

        sz = sd_json_variant_format(m, /* flags= */ 0, &text);
        if (sz < 0)
                return sz;
        assert(text[sz] == '\0');

        if (v->output_buffer_size + sz + 1 > VARLINK_BUFFER_MAX)
                return -ENOBUFS;

        if (DEBUG_LOGGING) {
                _cleanup_(erase_and_freep) char *censored_text = NULL;

                /* Suppress sensitive fields in the debug output */
                r = sd_json_variant_format(m, SD_JSON_FORMAT_CENSOR_SENSITIVE, &censored_text);
                if (r < 0)
                        return r;

                varlink_log(v, "Sending message: %s", censored_text);
        }

        if (v->output_buffer_size == 0) {

                free_and_replace(v->output_buffer, text);

                v->output_buffer_size = sz + 1;
                v->output_buffer_index = 0;

        } else if (v->output_buffer_index == 0) {

                if (!GREEDY_REALLOC(v->output_buffer, v->output_buffer_size + sz + 1))
                        return -ENOMEM;

                memcpy(v->output_buffer + v->output_buffer_size, text, sz + 1);
                v->output_buffer_size += sz + 1;
        } else {
                char *n;
                const size_t new_size = v->output_buffer_size + sz + 1;

                n = new(char, new_size);
                if (!n)
                        return -ENOMEM;

                memcpy(mempcpy(n, v->output_buffer + v->output_buffer_index, v->output_buffer_size), text, sz + 1);

                free_and_replace(v->output_buffer, n);
                v->output_buffer_size = new_size;
                v->output_buffer_index = 0;
        }

        if (sd_json_variant_is_sensitive_recursive(m))
                v->output_buffer_sensitive = true; /* Propagate sensitive flag */
        else
                text = mfree(text); /* No point in the erase_and_free() destructor declared above */

        return 0;
}

static int varlink_format_queue(sd_varlink *v) {
        int r;

        assert(v);

        /* Takes entries out of the output queue and formats them into the output buffer. But only if this
         * would not corrupt our fd message boundaries */

        while (v->output_queue) {
                _cleanup_free_ int *array = NULL;

                assert(v->n_output_queue > 0);

                VarlinkJsonQueueItem *q = v->output_queue;

                if (v->n_output_fds > 0) /* unwritten fds? if we'd add more we'd corrupt the fd message boundaries, hence wait */
                        return 0;

                if (q->n_fds > 0) {
                        array = newdup(int, q->fds, q->n_fds);
                        if (!array)
                                return -ENOMEM;
                }

                r = varlink_format_json(v, q->data);
                if (r < 0)
                        return r;

                /* Take possession of the queue element's fds */
                free(v->output_fds);
                v->output_fds = TAKE_PTR(array);
                v->n_output_fds = q->n_fds;
                q->n_fds = 0;

                LIST_REMOVE(queue, v->output_queue, q);
                if (!v->output_queue)
                        v->output_queue_tail = NULL;
                v->n_output_queue--;

                varlink_json_queue_item_free(q);
        }

        return 0;
}

static int varlink_enqueue_item(sd_varlink *v, VarlinkJsonQueueItem *q) {
        assert(v);
        assert(q);

        if (v->n_output_queue >= VARLINK_QUEUE_MAX)
                return -ENOBUFS;

        LIST_INSERT_AFTER(queue, v->output_queue, v->output_queue_tail, q);
        v->output_queue_tail = q;
        v->n_output_queue++;
        return 0;
}

static int varlink_enqueue_json(sd_varlink *v, sd_json_variant *m) {
        VarlinkJsonQueueItem *q;

        assert(v);
        assert(m);

        /* If there are no file descriptors to be queued and no queue entries yet we can shortcut things and
         * append this entry directly to the output buffer */
        if (v->n_pushed_fds == 0 && !v->output_queue)
                return varlink_format_json(v, m);

        if (v->n_output_queue >= VARLINK_QUEUE_MAX)
                return -ENOBUFS;

        /* Otherwise add a queue entry for this */
        q = varlink_json_queue_item_new(m, v->pushed_fds, v->n_pushed_fds);
        if (!q)
                return -ENOMEM;

        v->n_pushed_fds = 0; /* fds now belong to the queue entry */

        /* We already checked the precondition ourselves so this call cannot fail. */
        assert_se(varlink_enqueue_item(v, q) >= 0);

        return 0;
}

static int varlink_dispatch_method(sd_varlink *v) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *parameters = NULL;
        sd_varlink_method_flags_t flags = 0;
        const char *method = NULL;
        sd_json_variant *e;
        sd_varlink_method_t callback;
        const char *k;
        int r;

        assert(v);

        if (v->state != VARLINK_IDLE_SERVER)
                return 0;
        if (!v->current)
                return 0;

        if (!sd_json_variant_is_object(v->current))
                goto invalid;

        JSON_VARIANT_OBJECT_FOREACH(k, e, v->current) {

                if (streq(k, "method")) {
                        if (method)
                                goto invalid;
                        if (!sd_json_variant_is_string(e))
                                goto invalid;

                        method = sd_json_variant_string(e);

                } else if (streq(k, "parameters")) {
                        if (parameters)
                                goto invalid;
                        if (!sd_json_variant_is_object(e) && !sd_json_variant_is_null(e))
                                goto invalid;

                        parameters = sd_json_variant_ref(e);

                } else if (streq(k, "oneway")) {

                        if ((flags & (SD_VARLINK_METHOD_ONEWAY|SD_VARLINK_METHOD_MORE)) != 0)
                                goto invalid;

                        if (!sd_json_variant_is_boolean(e))
                                goto invalid;

                        if (sd_json_variant_boolean(e))
                                flags |= SD_VARLINK_METHOD_ONEWAY;

                } else if (streq(k, "more")) {

                        if ((flags & (SD_VARLINK_METHOD_ONEWAY|SD_VARLINK_METHOD_MORE)) != 0)
                                goto invalid;

                        if (!sd_json_variant_is_boolean(e))
                                goto invalid;

                        if (sd_json_variant_boolean(e))
                                flags |= SD_VARLINK_METHOD_MORE;

                } else
                        goto invalid;
        }

        if (!method)
                goto invalid;

        r = varlink_sanitize_incoming_parameters(&parameters);
        if (r < 0)
                goto fail;

        varlink_set_state(v, (flags & SD_VARLINK_METHOD_MORE)   ? VARLINK_PROCESSING_METHOD_MORE :
                             (flags & SD_VARLINK_METHOD_ONEWAY) ? VARLINK_PROCESSING_METHOD_ONEWAY :
                                                                  VARLINK_PROCESSING_METHOD);

        assert(v->server);

        /* First consult user supplied method implementations */
        callback = hashmap_get(v->server->methods, method);
        if (!callback) {
                if (streq(method, "org.varlink.service.GetInfo"))
                        callback = generic_method_get_info;
                else if (streq(method, "org.varlink.service.GetInterfaceDescription"))
                        callback = generic_method_get_interface_description;
        }

        if (callback) {
                bool invalid = false;

                v->current_method = hashmap_get(v->server->symbols, method);
                if (!v->current_method)
                        varlink_log(v, "No interface description defined for method '%s', not validating.", method);
                else {
                        const char *bad_field;

                        r = varlink_idl_validate_method_call(v->current_method, parameters, flags, &bad_field);
                        if (r == -EBADE) {
                                varlink_log_errno(v, r, "Method %s() called without 'more' flag, but flag needs to be set.",
                                                  method);

                                if (v->state == VARLINK_PROCESSING_METHOD) {
                                        r = sd_varlink_error(v, SD_VARLINK_ERROR_EXPECTED_MORE, NULL);
                                        /* If we didn't manage to enqueue an error response, then fail the
                                         * connection completely. Otherwise ignore the error from
                                         * sd_varlink_error() here, as it is synthesized from the function's
                                         * parameters. */
                                        if (r < 0 && VARLINK_STATE_WANTS_REPLY(v->state))
                                                goto fail;
                                }
                        } else if (r < 0) {
                                /* Please adjust test/units/end.sh when updating the log message. */
                                varlink_log_errno(v, r, "Parameters for method %s() didn't pass validation on field '%s': %m",
                                                  method, strna(bad_field));

                                if (VARLINK_STATE_WANTS_REPLY(v->state)) {
                                        r = sd_varlink_error_invalid_parameter_name(v, bad_field);
                                        /* If we didn't manage to enqueue an error response, then fail the connection completely. */
                                        if (r < 0 && VARLINK_STATE_WANTS_REPLY(v->state))
                                                goto fail;
                                }
                        }

                        invalid = r < 0;
                }

                if (!invalid) {
                        r = callback(v, parameters, flags, v->userdata);
                        if (VARLINK_STATE_WANTS_REPLY(v->state)) {
                                if (r < 0) {
                                        varlink_log_errno(v, r, "Callback for %s returned error: %m", method);

                                        /* We got an error back from the callback. Propagate it to the client
                                         * if the method call remains unanswered. */
                                        r = sd_varlink_error_errno(v, r);
                                } else if (v->sentinel) {
                                        if (v->previous) {
                                                r = varlink_enqueue_item(v, v->previous);
                                                if (r >= 0) {
                                                        TAKE_PTR(v->previous);
                                                        varlink_set_state(v, VARLINK_PROCESSED_METHOD);
                                                }
                                        } else {
                                                char *sentinel = TAKE_PTR(v->sentinel);

                                                /* Propagate the sentinel to the client if one was configured
                                                 * and no replies were enqueued by the callback. */
                                                if (sentinel == POINTER_MAX)
                                                        r = sd_varlink_reply(v, NULL);
                                                else
                                                        r = sd_varlink_error(v, sentinel, NULL);

                                                if (sentinel != POINTER_MAX)
                                                        free(sentinel);
                                        }
                                        if (r < 0)
                                                varlink_log_errno(v, r, "Failed to process sentinel for method '%s': %m", method);
                                } else {
                                        assert(!v->previous);
                                        r = 0;
                                }

                                /* If we didn't manage to enqueue a response, then fail the connection completely. */
                                if (r < 0 && VARLINK_STATE_WANTS_REPLY(v->state))
                                        goto fail;

                        } else
                                assert(!v->previous);
                }
        } else if (VARLINK_STATE_WANTS_REPLY(v->state)) {
                r = sd_varlink_errorbo(v, SD_VARLINK_ERROR_METHOD_NOT_FOUND, SD_JSON_BUILD_PAIR_STRING("method", method));
                /* If we didn't manage to enqueue an error response, then fail the connection completely. */
                if (r < 0 && VARLINK_STATE_WANTS_REPLY(v->state))
                        goto fail;
        }

        switch (v->state) {

        case VARLINK_PROCESSED_METHOD: /* Method call is fully processed */
        case VARLINK_PROCESSING_METHOD_ONEWAY: /* ditto */
                varlink_clear_current(v);
                varlink_set_state(v, VARLINK_IDLE_SERVER);
                break;

        case VARLINK_PROCESSING_METHOD: /* Method call wasn't replied to, will be replied to later */
                varlink_set_state(v, VARLINK_PENDING_METHOD);
                break;

        case VARLINK_PROCESSING_METHOD_MORE: /* No reply for a "more" message was sent, more to come */
                varlink_set_state(v, VARLINK_PENDING_METHOD_MORE);
                break;

        case VARLINK_DISCONNECTED: /* Handler called sd_varlink_close() on us, which is fine */
                break;

        default:
                assert_not_reached();
        }

        return 1;

invalid:
        r = -EINVAL;

fail:
        varlink_set_state(v, VARLINK_PROCESSING_FAILURE);
        varlink_dispatch_local_error(v, SD_VARLINK_ERROR_PROTOCOL);
        sd_varlink_close(v);

        return r;
}

_public_ int sd_varlink_process(sd_varlink *v) {
        int r;

        assert_return(v, -EINVAL);

        if (v->state == VARLINK_DISCONNECTED)
                return varlink_log_errno(v, SYNTHETIC_ERRNO(ENOTCONN), "Not connected.");

        sd_varlink_ref(v);

        r = varlink_write(v);
        if (r < 0)
                varlink_log_errno(v, r, "Write failed: %m");
        if (r != 0)
                goto finish;

        r = varlink_dispatch_reply(v);
        if (r < 0)
                varlink_log_errno(v, r, "Reply dispatch failed: %m");
        if (r != 0)
                goto finish;

        r = varlink_dispatch_method(v);
        if (r < 0)
                varlink_log_errno(v, r, "Method dispatch failed: %m");
        if (r != 0)
                goto finish;

        r = varlink_parse_message(v);
        if (r < 0)
                varlink_log_errno(v, r, "Message parsing failed: %m");
        if (r != 0)
                goto finish;

        r = varlink_read(v);
        if (r < 0)
                varlink_log_errno(v, r, "Read failed: %m");
        if (r != 0)
                goto finish;

        r = varlink_test_disconnect(v);
        assert(r >= 0);
        if (r != 0)
                goto finish;

        r = varlink_dispatch_disconnect(v);
        assert(r >= 0);
        if (r != 0)
                goto finish;

        r = varlink_test_timeout(v);
        assert(r >= 0);
        if (r != 0)
                goto finish;

        r = varlink_dispatch_timeout(v);
        assert(r >= 0);
        if (r != 0)
                goto finish;

finish:
        if (r >= 0 && v->defer_event_source) {
                int q;

                /* If we did some processing, make sure we are called again soon */
                q = sd_event_source_set_enabled(v->defer_event_source, r > 0 ? SD_EVENT_ON : SD_EVENT_OFF);
                if (q < 0)
                        r = varlink_log_errno(v, q, "Failed to enable deferred event source: %m");
        }

        if (r < 0) {
                if (VARLINK_STATE_IS_ALIVE(v->state))
                        /* Initiate disconnection */
                        varlink_set_state(v, VARLINK_PENDING_DISCONNECT);
                else
                        /* We failed while disconnecting, in that case close right away */
                        sd_varlink_close(v);
        }

        sd_varlink_unref(v);
        return r;
}

_public_ int sd_varlink_dispatch_again(sd_varlink *v) {
        int r;

        assert_return(v, -EINVAL);

        /* If a method call handler could not process the method call just yet (for example because it needed
         * some Polkit authentication first), then it can leave the call unanswered, do its thing, and then
         * ask to be dispatched a second time, via this call. It will then be called again, for the same
         * message */

        if (v->state == VARLINK_DISCONNECTED)
                return varlink_log_errno(v, SYNTHETIC_ERRNO(ENOTCONN), "Not connected.");
        if (!IN_SET(v->state, VARLINK_PENDING_METHOD, VARLINK_PENDING_METHOD_MORE))
                return varlink_log_errno(v, SYNTHETIC_ERRNO(EBUSY), "Connection has no pending method.");

        varlink_set_state(v, VARLINK_IDLE_SERVER);

        r = sd_event_source_set_enabled(v->defer_event_source, SD_EVENT_ON);
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to enable deferred event source: %m");

        return 0;
}

_public_ int sd_varlink_get_current_method(sd_varlink *v, const char **ret) {
        assert_return(v, -EINVAL);

        if (!v->current)
                return -ENODATA;

        sd_json_variant *p = sd_json_variant_by_key(v->current, "method");
        if (!p)
                return -ENODATA;

        const char *s = sd_json_variant_string(p);
        if (!s)
                return -ENODATA;

        if (ret)
                *ret = s;
        return 0;
}

_public_ int sd_varlink_get_current_parameters(sd_varlink *v, sd_json_variant **ret) {
        sd_json_variant *p;

        assert_return(v, -EINVAL);

        if (!v->current)
                return -ENODATA;

        if (!ret)
                return 0;

        p = sd_json_variant_by_key(v->current, "parameters");
        if (!p || sd_json_variant_is_null(p))
                return sd_json_variant_new_object(ret, NULL, 0);

        *ret = sd_json_variant_ref(p);
        return 0;
}

static void handle_revents(sd_varlink *v, int revents) {
        assert(v);

        if (v->connecting) {
                /* If we have seen POLLOUT or POLLHUP on a socket we are asynchronously waiting a connect()
                 * to complete on, we know we are ready. We don't read the connection error here though,
                 * we'll get the error on the next read() or write(). */
                if ((revents & (POLLOUT|POLLHUP)) == 0)
                        return;

                varlink_log(v, "Asynchronous connection completed.");
                v->connecting = false;
        } else {
                /* Note that we don't care much about POLLIN/POLLOUT here, we'll just try reading and writing
                 * what we can. However, we do care about POLLHUP to detect connection termination even if we
                 * momentarily don't want to read nor write anything. */

                if (!FLAGS_SET(revents, POLLHUP))
                        return;

                varlink_log(v, "Got POLLHUP from socket.");
                v->got_pollhup = true;
        }
}

_public_ int sd_varlink_wait(sd_varlink *v, uint64_t timeout) {
        int r, events;
        usec_t t;

        assert_return(v, -EINVAL);

        if (v->state == VARLINK_DISCONNECTED)
                return varlink_log_errno(v, SYNTHETIC_ERRNO(ENOTCONN), "Not connected.");

        r = sd_varlink_get_timeout(v, &t);
        if (r < 0)
                return r;
        if (t != USEC_INFINITY)
                t = usec_sub_unsigned(t, now(CLOCK_MONOTONIC));

        t = MIN(t, timeout);

        events = sd_varlink_get_events(v);
        if (events < 0)
                return events;

        struct pollfd pollfd[2];
        size_t n_poll_fd = 0;

        if (v->input_fd == v->output_fd) {
                pollfd[n_poll_fd++] = (struct pollfd) {
                        .fd = v->input_fd,
                        .events = events,
                };
        } else {
                pollfd[n_poll_fd++] = (struct pollfd) {
                        .fd = v->input_fd,
                        .events = events & POLLIN,
                };
                pollfd[n_poll_fd++] = (struct pollfd) {
                        .fd = v->output_fd,
                        .events = events & POLLOUT,
                };
        };

        r = ppoll_usec(pollfd, n_poll_fd, t);
        if (ERRNO_IS_NEG_TRANSIENT(r)) /* Treat EINTR as not a timeout, but also nothing happened, and
                                        * the caller gets a chance to call back into us */
                return 1;
        if (r <= 0)
                return r;

        /* Merge the seen events into one */
        int revents = 0;
        FOREACH_ARRAY(p, pollfd, n_poll_fd)
                revents |= p->revents;

        handle_revents(v, revents);
        return 1;
}

_public_ int sd_varlink_is_idle(sd_varlink *v) {
        assert_return(v, -EINVAL);

        /* Returns true if there's nothing pending on the connection anymore, i.e. we processed all incoming
         * or outgoing messages fully, or finished disconnection */

        return IN_SET(v->state, VARLINK_DISCONNECTED, VARLINK_IDLE_CLIENT, VARLINK_IDLE_SERVER);
}

_public_ int sd_varlink_is_connected(sd_varlink *v) {
        assert_return(v, -EINVAL);

        /* Returns true if the connection is still connected */

        return v->state != VARLINK_DISCONNECTED;
}

_public_ int sd_varlink_get_fd(sd_varlink *v) {

        assert_return(v, -EINVAL);

        if (v->state == VARLINK_DISCONNECTED)
                return varlink_log_errno(v, SYNTHETIC_ERRNO(ENOTCONN), "Not connected.");
        if (v->input_fd != v->output_fd)
                return varlink_log_errno(v, SYNTHETIC_ERRNO(EBADF), "Separate file descriptors for input/output set.");
        if (v->input_fd < 0)
                return varlink_log_errno(v, SYNTHETIC_ERRNO(EBADF), "No valid fd.");

        return v->input_fd;
}

_public_ int sd_varlink_get_input_fd(sd_varlink *v) {

        assert_return(v, -EINVAL);

        if (v->state == VARLINK_DISCONNECTED)
                return varlink_log_errno(v, SYNTHETIC_ERRNO(ENOTCONN), "Not connected.");
        if (v->input_fd < 0)
                return varlink_log_errno(v, SYNTHETIC_ERRNO(EBADF), "No valid input fd.");

        return v->input_fd;
}

_public_ int sd_varlink_get_output_fd(sd_varlink *v) {

        assert_return(v, -EINVAL);

        if (v->state == VARLINK_DISCONNECTED)
                return varlink_log_errno(v, SYNTHETIC_ERRNO(ENOTCONN), "Not connected.");
        if (v->output_fd < 0)
                return varlink_log_errno(v, SYNTHETIC_ERRNO(EBADF), "No valid output fd.");

        return v->output_fd;
}

_public_ int sd_varlink_get_events(sd_varlink *v) {
        int ret = 0;

        assert_return(v, -EINVAL);

        if (v->state == VARLINK_DISCONNECTED)
                return varlink_log_errno(v, SYNTHETIC_ERRNO(ENOTCONN), "Not connected.");

        if (v->connecting) /* When processing an asynchronous connect(), we only wait for EPOLLOUT, which
                            * tells us that the connection is now complete. Before that we should neither
                            * write() or read() from the fd. */
                return EPOLLOUT;

        if (!v->read_disconnected &&
            IN_SET(v->state, VARLINK_AWAITING_REPLY, VARLINK_AWAITING_REPLY_MORE, VARLINK_CALLING, VARLINK_COLLECTING, VARLINK_IDLE_SERVER) &&
            !v->current &&
            v->input_buffer_unscanned <= 0)
                ret |= EPOLLIN;

        if (!v->write_disconnected &&
            (v->output_queue ||
             v->output_buffer_size > 0))
                ret |= EPOLLOUT;

        return ret;
}

_public_ int sd_varlink_get_timeout(sd_varlink *v, uint64_t *ret) {
        assert_return(v, -EINVAL);

        if (v->state == VARLINK_DISCONNECTED)
                return varlink_log_errno(v, SYNTHETIC_ERRNO(ENOTCONN), "Not connected.");

        if (IN_SET(v->state, VARLINK_AWAITING_REPLY, VARLINK_AWAITING_REPLY_MORE, VARLINK_CALLING, VARLINK_COLLECTING) &&
            v->timeout != USEC_INFINITY) {
                if (ret)
                        *ret = usec_add(v->timestamp, v->timeout);
                return 1;
        } else {
                if (ret)
                        *ret = USEC_INFINITY;
                return 0;
        }
}

_public_ int sd_varlink_flush(sd_varlink *v) {
        int ret = 0, r;

        assert_return(v, -EINVAL);

        if (v->state == VARLINK_DISCONNECTED)
                return varlink_log_errno(v, SYNTHETIC_ERRNO(ENOTCONN), "Not connected.");

        for (;;) {
                if (v->output_buffer_size == 0)
                        break;
                if (v->write_disconnected)
                        return -ECONNRESET;

                r = varlink_write(v);
                if (r < 0)
                        return r;
                if (r > 0) {
                        ret = 1;
                        continue;
                }

                r = fd_wait_for_event(v->output_fd, POLLOUT, USEC_INFINITY);
                if (ERRNO_IS_NEG_TRANSIENT(r))
                        continue;
                if (r < 0)
                        return varlink_log_errno(v, r, "Poll failed on fd: %m");
                assert(r > 0);

                handle_revents(v, r);
        }

        return ret;
}

static void varlink_detach_server(sd_varlink *v) {
        sd_varlink_server *saved_server;

        assert(v);

        if (!v->server)
                return;

        if (v->server->by_uid &&
            v->ucred_acquired &&
            uid_is_valid(v->ucred.uid)) {
                unsigned c;

                c = PTR_TO_UINT(hashmap_get(v->server->by_uid, UID_TO_PTR(v->ucred.uid)));
                assert(c > 0);

                if (c == 1)
                        (void) hashmap_remove(v->server->by_uid, UID_TO_PTR(v->ucred.uid));
                else
                        (void) hashmap_replace(v->server->by_uid, UID_TO_PTR(v->ucred.uid), UINT_TO_PTR(c - 1));
        }

        assert(v->server->n_connections > 0);
        v->server->n_connections--;

        /* If this is a connection associated to a server, then let's disconnect the server and the
         * connection from each other. This drops the dangling reference that connect_callback() set up. But
         * before we release the references, let's call the disconnection callback if it is defined. */

        saved_server = TAKE_PTR(v->server);

        if (saved_server->disconnect_callback)
                saved_server->disconnect_callback(saved_server, v, saved_server->userdata);

        varlink_server_test_exit_on_idle(saved_server);
        sd_varlink_server_unref(saved_server);
        sd_varlink_unref(v);
}

_public_ int sd_varlink_close(sd_varlink *v) {
        assert_return(v, -EINVAL);

        if (v->state == VARLINK_DISCONNECTED)
                return 0;

        varlink_set_state(v, VARLINK_DISCONNECTED);

        /* Let's take a reference first, since varlink_detach_server() might drop the final (dangling) ref
         * which would destroy us before we can call varlink_clear() */
        sd_varlink_ref(v);
        varlink_detach_server(v);
        varlink_clear(v);
        sd_varlink_unref(v);

        return 1;
}

_public_ sd_varlink* sd_varlink_close_unref(sd_varlink *v) {
        if (!v)
                return NULL;

        (void) sd_varlink_close(v);
        return sd_varlink_unref(v);
}

_public_ sd_varlink* sd_varlink_flush_close_unref(sd_varlink *v) {
        if (!v)
                return NULL;

        (void) sd_varlink_flush(v);
        return sd_varlink_close_unref(v);
}

_public_ int sd_varlink_send(sd_varlink *v, const char *method, sd_json_variant *parameters) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *m = NULL;
        int r;

        assert_return(v, -EINVAL);
        assert_return(method, -EINVAL);

        if (v->state == VARLINK_DISCONNECTED)
                return varlink_log_errno(v, SYNTHETIC_ERRNO(ENOTCONN), "Not connected.");

        /* We allow enqueuing multiple method calls at once! */
        if (!IN_SET(v->state, VARLINK_IDLE_CLIENT, VARLINK_AWAITING_REPLY))
                return varlink_log_errno(v, SYNTHETIC_ERRNO(EBUSY), "Connection busy.");

        r = sd_json_buildo(
                        &m,
                        SD_JSON_BUILD_PAIR_STRING("method", method),
                        JSON_BUILD_PAIR_VARIANT_NON_EMPTY("parameters", parameters),
                        SD_JSON_BUILD_PAIR_BOOLEAN("oneway", true));
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to build json message: %m");

        r = varlink_enqueue_json(v, m);
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to enqueue json message: %m");

        /* No state change here, this is one-way only after all */
        v->timestamp = now(CLOCK_MONOTONIC);
        return 0;
}

_public_ int sd_varlink_sendb(sd_varlink *v, const char *method, ...) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *parameters = NULL;
        va_list ap;
        int r;

        assert_return(v, -EINVAL);

        va_start(ap, method);
        r = sd_json_buildv(&parameters, ap);
        va_end(ap);

        if (r < 0)
                return varlink_log_errno(v, r, "Failed to build json message: %m");

        return sd_varlink_send(v, method, parameters);
}

_public_ int sd_varlink_invoke(sd_varlink *v, const char *method, sd_json_variant *parameters) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *m = NULL;
        int r;

        assert_return(v, -EINVAL);
        assert_return(method, -EINVAL);

        if (v->state == VARLINK_DISCONNECTED)
                return varlink_log_errno(v, SYNTHETIC_ERRNO(ENOTCONN), "Not connected.");

        /* We allow enqueuing multiple method calls at once! */
        if (!IN_SET(v->state, VARLINK_IDLE_CLIENT, VARLINK_AWAITING_REPLY))
                return varlink_log_errno(v, SYNTHETIC_ERRNO(EBUSY), "Connection busy.");

        r = sd_json_buildo(
                        &m,
                        SD_JSON_BUILD_PAIR_STRING("method", method),
                        JSON_BUILD_PAIR_VARIANT_NON_EMPTY("parameters", parameters));
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to build json message: %m");

        r = varlink_enqueue_json(v, m);
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to enqueue json message: %m");

        varlink_set_state(v, VARLINK_AWAITING_REPLY);
        v->n_pending++;
        v->timestamp = now(CLOCK_MONOTONIC);

        return 0;
}

_public_ int sd_varlink_invokeb(sd_varlink *v, const char *method, ...) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *parameters = NULL;
        va_list ap;
        int r;

        assert_return(v, -EINVAL);

        va_start(ap, method);
        r = sd_json_buildv(&parameters, ap);
        va_end(ap);

        if (r < 0)
                return varlink_log_errno(v, r, "Failed to build json message: %m");

        return sd_varlink_invoke(v, method, parameters);
}

_public_ int sd_varlink_observe(sd_varlink *v, const char *method, sd_json_variant *parameters) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *m = NULL;
        int r;

        assert_return(v, -EINVAL);
        assert_return(method, -EINVAL);

        if (v->state == VARLINK_DISCONNECTED)
                return varlink_log_errno(v, SYNTHETIC_ERRNO(ENOTCONN), "Not connected.");

        /* Note that we don't allow enqueuing multiple method calls when we are in more/continues mode! We
         * thus insist on an idle client here. */
        if (v->state != VARLINK_IDLE_CLIENT)
                return varlink_log_errno(v, SYNTHETIC_ERRNO(EBUSY), "Connection busy.");

        r = sd_json_buildo(
                        &m,
                        SD_JSON_BUILD_PAIR_STRING("method", method),
                        JSON_BUILD_PAIR_VARIANT_NON_EMPTY("parameters", parameters),
                        SD_JSON_BUILD_PAIR_BOOLEAN("more", true));
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to build json message: %m");

        r = varlink_enqueue_json(v, m);
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to enqueue json message: %m");

        varlink_set_state(v, VARLINK_AWAITING_REPLY_MORE);
        v->n_pending++;
        v->timestamp = now(CLOCK_MONOTONIC);

        return 0;
}

_public_ int sd_varlink_observeb(sd_varlink *v, const char *method, ...) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *parameters = NULL;
        va_list ap;
        int r;

        assert_return(v, -EINVAL);

        va_start(ap, method);
        r = sd_json_buildv(&parameters, ap);
        va_end(ap);

        if (r < 0)
                return varlink_log_errno(v, r, "Failed to build json message: %m");

        return sd_varlink_observe(v, method, parameters);
}

_public_ int sd_varlink_call_full(
                sd_varlink *v,
                const char *method,
                sd_json_variant *parameters,
                sd_json_variant **ret_parameters,
                const char **ret_error_id,
                sd_varlink_reply_flags_t *ret_flags) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *m = NULL;
        int r;

        assert_return(v, -EINVAL);
        assert_return(method, -EINVAL);

        if (v->state == VARLINK_DISCONNECTED)
                return varlink_log_errno(v, SYNTHETIC_ERRNO(ENOTCONN), "Not connected.");
        if (v->state != VARLINK_IDLE_CLIENT)
                return varlink_log_errno(v, SYNTHETIC_ERRNO(EBUSY), "Connection busy.");

        assert(v->n_pending == 0); /* n_pending can't be > 0 if we are in VARLINK_IDLE_CLIENT state */

        /* If there was still a reply pinned from a previous call, now it's the time to get rid of it, so
         * that we can assign a new reply shortly. */
        varlink_clear_current(v);

        r = sd_json_buildo(
                        &m,
                        SD_JSON_BUILD_PAIR_STRING("method", method),
                        JSON_BUILD_PAIR_VARIANT_NON_EMPTY("parameters", parameters));
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to build json message: %m");

        r = varlink_enqueue_json(v, m);
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to enqueue json message: %m");

        varlink_set_state(v, VARLINK_CALLING);
        v->n_pending++;
        v->timestamp = now(CLOCK_MONOTONIC);

        while (v->state == VARLINK_CALLING) {
                r = sd_varlink_process(v);
                if (r < 0)
                        return r;
                if (r > 0)
                        continue;

                r = sd_varlink_wait(v, USEC_INFINITY);
                if (r < 0)
                        return r;
        }

        switch (v->state) {

        case VARLINK_CALLED: {
                assert(v->current);

                varlink_set_state(v, VARLINK_IDLE_CLIENT);
                assert(v->n_pending == 1);
                v->n_pending--;

                sd_json_variant *e = sd_json_variant_by_key(v->current, "error"),
                        *p = sd_json_variant_by_key(v->current, "parameters");

                /* If caller doesn't ask for the error string, then let's return an error code in case of failure */
                if (!ret_error_id && e)
                        return sd_varlink_error_to_errno(sd_json_variant_string(e), p);

                if (ret_parameters)
                        *ret_parameters = p;
                if (ret_error_id)
                        *ret_error_id = e ? sd_json_variant_string(e) : NULL;
                if (ret_flags)
                        *ret_flags = v->current_reply_flags;

                return 1;
        }

        case VARLINK_PENDING_DISCONNECT:
        case VARLINK_DISCONNECTED:
                return varlink_log_errno(v, SYNTHETIC_ERRNO(ECONNRESET), "Connection was closed.");

        case VARLINK_PENDING_TIMEOUT:
                return varlink_log_errno(v, SYNTHETIC_ERRNO(ETIME), "Connection timed out.");

        default:
                assert_not_reached();
        }
}

_public_ int sd_varlink_call(
                sd_varlink *v,
                const char *method,
                sd_json_variant *parameters,
                sd_json_variant **ret_parameters,
                const char **ret_error_id) {

        return sd_varlink_call_full(v, method, parameters, ret_parameters, ret_error_id, NULL);
}

_public_ int sd_varlink_callb_ap(
                sd_varlink *v,
                const char *method,
                sd_json_variant **ret_parameters,
                const char **ret_error_id,
                sd_varlink_reply_flags_t *ret_flags,
                va_list ap) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *parameters = NULL;
        int r;

        assert_return(v, -EINVAL);
        assert_return(method, -EINVAL);

        r = sd_json_buildv(&parameters, ap);
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to build json message: %m");

        return sd_varlink_call_full(v, method, parameters, ret_parameters, ret_error_id, ret_flags);
}

_public_ int sd_varlink_callb(
                sd_varlink *v,
                const char *method,
                sd_json_variant **ret_parameters,
                const char **ret_error_id,
                ...) {

        va_list ap;
        int r;

        va_start(ap, ret_error_id);
        r = sd_varlink_callb_ap(v, method, ret_parameters, ret_error_id, NULL, ap);
        va_end(ap);
        return r;
}

_public_ int sd_varlink_callb_full(
                sd_varlink *v,
                const char *method,
                sd_json_variant **ret_parameters,
                const char **ret_error_id,
                sd_varlink_reply_flags_t *ret_flags,
                ...) {

        va_list ap;
        int r;

        va_start(ap, ret_flags);
        r = sd_varlink_callb_ap(v, method, ret_parameters, ret_error_id, ret_flags, ap);
        va_end(ap);
        return r;
}

_public_ int sd_varlink_collect_full(
                sd_varlink *v,
                const char *method,
                sd_json_variant *parameters,
                sd_json_variant **ret_parameters,
                const char **ret_error_id,
                sd_varlink_reply_flags_t *ret_flags) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *m = NULL, *collected = NULL;
        int r;

        assert_return(v, -EINVAL);
        assert_return(method, -EINVAL);

        if (v->state == VARLINK_DISCONNECTED)
                return varlink_log_errno(v, SYNTHETIC_ERRNO(ENOTCONN), "Not connected.");
        if (v->state != VARLINK_IDLE_CLIENT)
                return varlink_log_errno(v, SYNTHETIC_ERRNO(EBUSY), "Connection busy.");

        assert(v->n_pending == 0); /* n_pending can't be > 0 if we are in VARLINK_IDLE_CLIENT state */

        /* If there was still a reply pinned from a previous call, now it's the time to get rid of it, so
         * that we can assign a new reply shortly. */
        varlink_clear_current(v);

        r = sd_json_buildo(
                        &m,
                        SD_JSON_BUILD_PAIR_STRING("method", method),
                        JSON_BUILD_PAIR_VARIANT_NON_EMPTY("parameters", parameters),
                        SD_JSON_BUILD_PAIR_BOOLEAN("more", true));
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to build json message: %m");

        r = varlink_enqueue_json(v, m);
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to enqueue json message: %m");

        varlink_set_state(v, VARLINK_COLLECTING);
        v->n_pending++;
        v->timestamp = now(CLOCK_MONOTONIC);

        for (;;) {
                while (v->state == VARLINK_COLLECTING) {
                        r = sd_varlink_process(v);
                        if (r < 0)
                                return r;
                        if (r > 0)
                                continue;

                        r = sd_varlink_wait(v, USEC_INFINITY);
                        if (r < 0)
                                return r;
                }

                switch (v->state) {

                case VARLINK_COLLECTING_REPLY: {
                        assert(v->current);

                        sd_json_variant *e = sd_json_variant_by_key(v->current, "error"),
                                *p = sd_json_variant_by_key(v->current, "parameters");

                        /* Unless there is more to collect we reset state to idle */
                        if (!FLAGS_SET(v->current_reply_flags, SD_VARLINK_REPLY_CONTINUES)) {
                                varlink_set_state(v, VARLINK_IDLE_CLIENT);
                                assert(v->n_pending == 1);
                                v->n_pending--;
                        }

                        if (e) {
                                if (!ret_error_id)
                                        return sd_varlink_error_to_errno(sd_json_variant_string(e), p);

                                if (ret_parameters)
                                        *ret_parameters = p;
                                if (ret_error_id)
                                        *ret_error_id = sd_json_variant_string(e);
                                if (ret_flags)
                                        *ret_flags = v->current_reply_flags;

                                return 1;
                        }

                        if (sd_json_variant_elements(collected) >= VARLINK_COLLECT_MAX)
                                return varlink_log_errno(v, SYNTHETIC_ERRNO(E2BIG), "Number of reply messages grew too large (%zu) while collecting.", sd_json_variant_elements(collected));

                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *empty = NULL;
                        if (!p) {
                                r = sd_json_variant_new_array(&empty, /* array= */ NULL, /* n= */ 0);
                                if (r < 0)
                                        return r;

                                p = empty;
                        }

                        r = sd_json_variant_append_array(&collected, p);
                        if (r < 0)
                                return varlink_log_errno(v, r, "Failed to append JSON object to array: %m");

                        if (FLAGS_SET(v->current_reply_flags, SD_VARLINK_REPLY_CONTINUES)) {
                                /* There's more to collect, continue */
                                varlink_clear_current(v);
                                varlink_set_state(v, VARLINK_COLLECTING);
                                continue;
                        }

                        if (ret_parameters)
                                /* Install the collection array in the connection object, so that we can hand
                                 * out a pointer to it without passing over ownership, to make it work more
                                 * alike regular method call replies */
                                *ret_parameters = v->current_collected = TAKE_PTR(collected);
                        if (ret_error_id)
                                *ret_error_id = NULL;
                        if (ret_flags)
                                *ret_flags = v->current_reply_flags;

                        return 1;
                }

                case VARLINK_PENDING_DISCONNECT:
                case VARLINK_DISCONNECTED:
                        return varlink_log_errno(v, SYNTHETIC_ERRNO(ECONNRESET), "Connection was closed.");

                case VARLINK_PENDING_TIMEOUT:
                        return varlink_log_errno(v, SYNTHETIC_ERRNO(ETIME), "Connection timed out.");

                default:
                        assert_not_reached();
                }
        }
}

_public_ int sd_varlink_collect(
                sd_varlink *v,
                const char *method,
                sd_json_variant *parameters,
                sd_json_variant **ret_parameters,
                const char **ret_error_id) {

        return sd_varlink_collect_full(v, method, parameters, ret_parameters, ret_error_id, NULL);
}

_public_ int sd_varlink_collectb(
                sd_varlink *v,
                const char *method,
                sd_json_variant **ret_parameters,
                const char **ret_error_id,
                ...) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *parameters = NULL;
        va_list ap;
        int r;

        assert_return(v, -EINVAL);

        va_start(ap, ret_error_id);
        r = sd_json_buildv(&parameters, ap);
        va_end(ap);

        if (r < 0)
                return varlink_log_errno(v, r, "Failed to build json message: %m");

        return sd_varlink_collect_full(v, method, parameters, ret_parameters, ret_error_id, NULL);
}

_public_ int sd_varlink_reply(sd_varlink *v, sd_json_variant *parameters) {
        int r;

        assert_return(v, -EINVAL);

        if (v->state == VARLINK_DISCONNECTED)
                return varlink_log_errno(v, SYNTHETIC_ERRNO(ENOTCONN), "Not connected.");

        if (!IN_SET(v->state,
                    VARLINK_PROCESSING_METHOD, VARLINK_PROCESSING_METHOD_MORE,
                    VARLINK_PENDING_METHOD, VARLINK_PENDING_METHOD_MORE))
                return varlink_log_errno(v, SYNTHETIC_ERRNO(EBUSY), "Connection busy.");

        bool more = IN_SET(v->state, VARLINK_PROCESSING_METHOD_MORE, VARLINK_PENDING_METHOD_MORE);

        /* Validate parameters BEFORE sanitization */
        if (v->current_method) {
                const char *bad_field = NULL;

                r = varlink_idl_validate_method_reply(v->current_method, parameters, more && v->sentinel ? SD_VARLINK_REPLY_CONTINUES : 0, &bad_field);
                if (r == -EBADE)
                        varlink_log_errno(v, r, "Method reply for %s() has 'continues' flag set, but IDL structure doesn't allow that, ignoring: %m",
                                          v->current_method->name);
                else if (r < 0)
                        /* Please adjust test/units/end.sh when updating the log message. */
                        varlink_log_errno(v, r, "Return parameters for method reply %s() didn't pass validation on field '%s', ignoring: %m",
                                          v->current_method->name, strna(bad_field));
        }

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *m = NULL;
        r = sd_json_buildo(&m, JSON_BUILD_PAIR_VARIANT_NON_EMPTY("parameters", parameters));
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to build json message: %m");

        if (more && v->sentinel) {
                if (v->previous) {
                        r = sd_json_variant_set_field_boolean(&v->previous->data, "continues", true);
                        if (r < 0)
                                return r;

                        r = varlink_enqueue_item(v, v->previous);
                        if (r < 0)
                                return varlink_log_errno(v, r, "Failed to enqueue json message: %m");
                }

                v->previous = varlink_json_queue_item_new(m, v->pushed_fds, v->n_pushed_fds);
                if (!v->previous)
                        return -ENOMEM;

                v->n_pushed_fds = 0; /* fds now belong to the queue entry */
                return 1;
        }

        r = varlink_enqueue_json(v, m);
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to enqueue json message: %m");

        if (IN_SET(v->state, VARLINK_PENDING_METHOD, VARLINK_PENDING_METHOD_MORE)) {
                /* We just replied to a method call that was let hanging for a while (i.e. we were outside of
                 * the varlink_dispatch_method() stack frame), which means with this reply we are ready to
                 * process further messages. */
                varlink_clear_current(v);
                varlink_set_state(v, VARLINK_IDLE_SERVER);
        } else
                /* We replied to a method call from within the varlink_dispatch_method() stack frame), which
                 * means we should it handle the rest of the state engine. */
                varlink_set_state(v, VARLINK_PROCESSED_METHOD);

        return 1;
}

_public_ int sd_varlink_replyb(sd_varlink *v, ...) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *parameters = NULL;
        va_list ap;
        int r;

        assert_return(v, -EINVAL);

        va_start(ap, v);
        r = sd_json_buildv(&parameters, ap);
        va_end(ap);

        if (r < 0)
                return r;

        return sd_varlink_reply(v, parameters);
}

_public_ int sd_varlink_reset_fds(sd_varlink *v) {
        assert_return(v, -EINVAL);

        /* Closes all currently pending fds to send. This may be used whenever the caller is in the process
         * of putting together a message with fds, and then eventually something fails and they need to
         * rollback the fds. Note that this is implicitly called whenever an error reply is sent, see
         * below. */

        close_many(v->output_fds, v->n_output_fds);
        v->n_output_fds = 0;
        return 0;
}

_public_ int sd_varlink_error(sd_varlink *v, const char *error_id, sd_json_variant *parameters) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *m = NULL;
        int r;

        assert_return(v, -EINVAL);
        assert_return(error_id, -EINVAL);

        if (v->state == VARLINK_DISCONNECTED)
                return varlink_log_errno(v, SYNTHETIC_ERRNO(ENOTCONN), "Not connected.");
        if (!IN_SET(v->state,
                    VARLINK_PROCESSING_METHOD, VARLINK_PROCESSING_METHOD_MORE,
                    VARLINK_PENDING_METHOD, VARLINK_PENDING_METHOD_MORE))
                return varlink_log_errno(v, SYNTHETIC_ERRNO(EBUSY), "Connection busy.");

        if (v->previous) {
                r = sd_json_variant_set_field_boolean(&v->previous->data, "continues", true);
                if (r < 0)
                        return r;

                /* If we have a previous reply still ready make sure we queue it before the error. We only
                 * ever set "previous" if we're in a streaming method so we pass more=true unconditionally
                 * here as we know we're still going to queue an error afterwards. */
                r = varlink_enqueue_item(v, v->previous);
                if (r < 0)
                        return varlink_log_errno(v, r, "Failed to enqueue json message: %m");

                TAKE_PTR(v->previous);
        }

        /* Reset the list of pushed file descriptors before sending an error reply. We do this here to
         * simplify code that puts together a complex reply message with fds, and half-way something
         * fails. In that case the pushed fds need to be flushed out again. Under the assumption that it
         * never makes sense to send fds along with errors we simply flush them out here beforehand, so that
         * the callers don't need to do this explicitly. */
        sd_varlink_reset_fds(v);

        /* Validate parameters BEFORE sanitization */
        sd_varlink_symbol *symbol = hashmap_get(v->server->symbols, error_id);
        if (!symbol)
                varlink_log(v, "No interface description defined for error '%s', not validating.", error_id);
        else {
                const char *bad_field = NULL;

                r = varlink_idl_validate_error(symbol, parameters, &bad_field);
                if (r < 0)
                        /* Please adjust test/units/end.sh when updating the log message. */
                        varlink_log_errno(v, r, "Parameters for error %s didn't pass validation on field '%s', ignoring: %m",
                                          error_id, strna(bad_field));
        }

        r = sd_json_buildo(
                        &m,
                        SD_JSON_BUILD_PAIR_STRING("error", error_id),
                        JSON_BUILD_PAIR_VARIANT_NON_EMPTY("parameters", parameters));
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to build json message: %m");

        r = varlink_enqueue_json(v, m);
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to enqueue json message: %m");

        if (IN_SET(v->state, VARLINK_PENDING_METHOD, VARLINK_PENDING_METHOD_MORE)) {
                varlink_clear_current(v);
                varlink_set_state(v, VARLINK_IDLE_SERVER);
        } else
                varlink_set_state(v, VARLINK_PROCESSED_METHOD);

        /* Everything worked. Let's now return the error we got passed as input as negative errno, so that
         * programs can just do "return sd_varlink_error();" and get both: a friendly error reply to clients,
         * and an error return from the current stack frame. */
        return sd_varlink_error_to_errno(error_id, parameters);
}

_public_ int sd_varlink_errorb(sd_varlink *v, const char *error_id, ...) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *parameters = NULL;
        va_list ap;
        int r;

        assert_return(v, -EINVAL);
        assert_return(error_id, -EINVAL);

        va_start(ap, error_id);
        r = sd_json_buildv(&parameters, ap);
        va_end(ap);

        if (r < 0)
                return varlink_log_errno(v, r, "Failed to build json message: %m");

        return sd_varlink_error(v, error_id, parameters);
}

_public_ int sd_varlink_error_invalid_parameter(sd_varlink *v, sd_json_variant *parameters) {
        int r;

        assert_return(v, -EINVAL);
        assert_return(parameters, -EINVAL);

        /* We expect to be called in one of two ways: the 'parameters' argument is a string variant in which
         * case it is the parameter key name that is invalid. Or the 'parameters' argument is an object
         * variant in which case we'll pull out the first key. The latter mode is useful in functions that
         * don't expect any arguments. */

        /* varlink_error(...) expects a json object as the third parameter. Passing a string variant causes
         * parameter sanitization to fail, and it returns -EINVAL. */

        if (sd_json_variant_is_string(parameters)) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *parameters_obj = NULL;

                r = sd_json_buildo(&parameters_obj,SD_JSON_BUILD_PAIR_VARIANT("parameter", parameters));
                if (r < 0)
                        return r;

                return sd_varlink_error(v, SD_VARLINK_ERROR_INVALID_PARAMETER, parameters_obj);
        }

        if (sd_json_variant_is_object(parameters) &&
            sd_json_variant_elements(parameters) > 0) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *parameters_obj = NULL;

                r = sd_json_buildo(&parameters_obj, SD_JSON_BUILD_PAIR_VARIANT("parameter", sd_json_variant_by_index(parameters, 0)));
                if (r < 0)
                        return r;

                return sd_varlink_error(v, SD_VARLINK_ERROR_INVALID_PARAMETER, parameters_obj);
        }

        return -EINVAL;
}

_public_ int sd_varlink_error_invalid_parameter_name(sd_varlink *v, const char *name) {
        return sd_varlink_errorbo(
                        v,
                        SD_VARLINK_ERROR_INVALID_PARAMETER,
                        SD_JSON_BUILD_PAIR_STRING("parameter", name));
}

_public_ int sd_varlink_error_errno(sd_varlink *v, int error) {

        /* This generates a system error return that includes the Linux error number, and error name. The
         * error number is kinda Linux specific (and to some degree the error name too), hence let's indicate
         * the origin of the system error. This way interpretation of the error should not leave questions
         * open, even to foreign systems. */

        error = abs(error);
        const char *name = errno_name_no_fallback(error);

        return sd_varlink_errorbo(
                        v,
                        SD_VARLINK_ERROR_SYSTEM,
                        SD_JSON_BUILD_PAIR_STRING("origin", "linux"),
                        SD_JSON_BUILD_PAIR_INTEGER("errno", error),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("errnoName", name));
}

_public_ int sd_varlink_notify(sd_varlink *v, sd_json_variant *parameters) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *m = NULL;
        int r;

        assert_return(v, -EINVAL);

        if (v->sentinel)
                return varlink_log_errno(v, SYNTHETIC_ERRNO(EINVAL), "Cannot use sd_varlink_notify() on method with sentinel set");

        assert(!v->previous);

        if (v->state == VARLINK_DISCONNECTED)
                return varlink_log_errno(v, SYNTHETIC_ERRNO(ENOTCONN), "Not connected.");

        /* If we want to reply with a notify connection but the caller didn't set "more", then return an
         * error indicating that we expected to be called with "more" set */
        if (IN_SET(v->state, VARLINK_PROCESSING_METHOD, VARLINK_PENDING_METHOD))
                return sd_varlink_error(v, SD_VARLINK_ERROR_EXPECTED_MORE, NULL);

        if (!IN_SET(v->state, VARLINK_PROCESSING_METHOD_MORE, VARLINK_PENDING_METHOD_MORE))
                return varlink_log_errno(v, SYNTHETIC_ERRNO(EBUSY), "Connection busy.");

        /* Validate parameters BEFORE sanitization */
        if (v->current_method) {
                const char *bad_field = NULL;

                r = varlink_idl_validate_method_reply(v->current_method, parameters, SD_VARLINK_REPLY_CONTINUES, &bad_field);
                if (r == -EBADE)
                        varlink_log_errno(v, r, "Method reply for %s() has 'continues' flag set, but IDL structure doesn't allow that, ignoring: %m",
                                          v->current_method->name);
                else if (r < 0)
                        /* Please adjust test/units/end.sh when updating the log message. */
                        varlink_log_errno(v, r, "Return parameters for method reply %s() didn't pass validation on field '%s', ignoring: %m",
                                          v->current_method->name, strna(bad_field));
        }

        r = sd_json_buildo(
                        &m,
                        JSON_BUILD_PAIR_VARIANT_NON_EMPTY("parameters", parameters),
                        SD_JSON_BUILD_PAIR_BOOLEAN("continues", true));
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to build json message: %m");

        r = varlink_enqueue_json(v, m);
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to enqueue json message: %m");

        /* No state change, as more is coming */
        return 1;
}

_public_ int sd_varlink_notifyb(sd_varlink *v, ...) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *parameters = NULL;
        va_list ap;
        int r;

        assert_return(v, -EINVAL);

        va_start(ap, v);
        r = sd_json_buildv(&parameters, ap);
        va_end(ap);

        if (r < 0)
                return varlink_log_errno(v, r, "Failed to build json message: %m");

        return sd_varlink_notify(v, parameters);
}

_public_ int sd_varlink_dispatch(sd_varlink *v, sd_json_variant *parameters, const sd_json_dispatch_field dispatch_table[], void *userdata) {
        const char *bad_field = NULL;
        int r;

        assert_return(v, -EINVAL);

        /* A wrapper around json_dispatch_full() that returns a nice InvalidParameter error if we hit a problem with some field. */

        /* sd_json_dispatch_full() now handles NULL parameters gracefully */
        r = sd_json_dispatch_full(parameters, dispatch_table, /* bad= */ NULL, /* flags= */ 0, userdata, &bad_field);
        if (r < 0) {
                if (bad_field)
                        return sd_varlink_error_invalid_parameter_name(v, bad_field);
                return r;
        }

        return 0;
}

_public_ int sd_varlink_bind_reply(sd_varlink *v, sd_varlink_reply_t reply) {
        assert_return(v, -EINVAL);

        if (reply && v->reply_callback && reply != v->reply_callback)
                return varlink_log_errno(v, SYNTHETIC_ERRNO(EBUSY), "A different callback was already set.");

        v->reply_callback = reply;

        return 0;
}

_public_ void* sd_varlink_set_userdata(sd_varlink *v, void *userdata) {
        void *old;

        assert_return(v, NULL);

        old = v->userdata;
        v->userdata = userdata;

        return old;
}

_public_ void* sd_varlink_get_userdata(sd_varlink *v) {
        assert_return(v, NULL);

        return v->userdata;
}

static int varlink_acquire_ucred(sd_varlink *v) {
        int r;

        assert(v);

        if (v->ucred_acquired)
                return 0;

        /* If we are connected asymmetrically, let's refuse, since it's not clear if caller wants to know
         * peer on read or write fd */
        if (v->input_fd != v->output_fd)
                return -EBADF;

        r = getpeercred(v->input_fd, &v->ucred);
        if (r < 0)
                return r;

        v->ucred_acquired = true;
        return 0;
}

_public_ int sd_varlink_get_peer_uid(sd_varlink *v, uid_t *ret) {
        int r;

        assert_return(v, -EINVAL);
        assert_return(ret, -EINVAL);

        r = varlink_acquire_ucred(v);
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to acquire credentials: %m");

        if (!uid_is_valid(v->ucred.uid))
                return varlink_log_errno(v, SYNTHETIC_ERRNO(ENODATA), "Peer UID is invalid.");

        *ret = v->ucred.uid;
        return 0;
}

_public_ int sd_varlink_get_peer_gid(sd_varlink *v, gid_t *ret) {
        int r;

        assert_return(v, -EINVAL);
        assert_return(ret, -EINVAL);

        r = varlink_acquire_ucred(v);
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to acquire credentials: %m");

        if (!gid_is_valid(v->ucred.gid))
                return varlink_log_errno(v, SYNTHETIC_ERRNO(ENODATA), "Peer GID is invalid.");

        *ret = v->ucred.gid;
        return 0;
}

_public_ int sd_varlink_get_peer_pid(sd_varlink *v, pid_t *ret) {
        int r;

        assert_return(v, -EINVAL);
        assert_return(ret, -EINVAL);

        r = varlink_acquire_ucred(v);
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to acquire credentials: %m");

        if (!pid_is_valid(v->ucred.pid))
                return varlink_log_errno(v, SYNTHETIC_ERRNO(ENODATA), "Peer uid is invalid.");

        *ret = v->ucred.pid;
        return 0;
}

_public_ int sd_varlink_get_peer_pidfd(sd_varlink *v) {
        assert_return(v, -EINVAL);

        if (v->peer_pidfd >= 0)
                return v->peer_pidfd;

        if (v->input_fd != v->output_fd)
                return -EBADF;

        v->peer_pidfd = getpeerpidfd(v->input_fd);
        if (v->peer_pidfd < 0)
                return varlink_log_errno(v, v->peer_pidfd, "Failed to acquire pidfd of peer: %m");

        return v->peer_pidfd;
}

_public_ int sd_varlink_set_relative_timeout(sd_varlink *v, uint64_t timeout) {
        assert_return(v, -EINVAL);

        /* If set to 0, reset to default value */
        v->timeout = timeout == 0 ? VARLINK_DEFAULT_TIMEOUT_USEC : timeout;
        return 0;
}

_public_ sd_varlink_server *sd_varlink_get_server(sd_varlink *v) {
        assert_return(v, NULL);

        return v->server;
}

_public_ int sd_varlink_set_description(sd_varlink *v, const char *description) {
        assert_return(v, -EINVAL);

        return free_and_strdup(&v->description, description);
}

_public_ const char* sd_varlink_get_description(sd_varlink *v) {
        assert_return(v, NULL);

        return v->description;
}

static int io_callback(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        sd_varlink *v = ASSERT_PTR(userdata);

        assert(s);

        handle_revents(v, revents);
        (void) sd_varlink_process(v);

        return 1;
}

static int time_callback(sd_event_source *s, uint64_t usec, void *userdata) {
        sd_varlink *v = ASSERT_PTR(userdata);

        assert(s);

        (void) sd_varlink_process(v);
        return 1;
}

static int defer_callback(sd_event_source *s, void *userdata) {
        sd_varlink *v = ASSERT_PTR(userdata);

        assert(s);

        (void) sd_varlink_process(v);
        return 1;
}

static int prepare_callback(sd_event_source *s, void *userdata) {
        sd_varlink *v = ASSERT_PTR(userdata);
        int r, e;
        usec_t until;
        bool have_timeout;

        assert(s);

        e = sd_varlink_get_events(v);
        if (e < 0)
                return e;

        if (v->input_event_source == v->output_event_source)
                /* Same fd for input + output */
                r = sd_event_source_set_io_events(v->input_event_source, e);
        else {
                r = sd_event_source_set_io_events(v->input_event_source, e & EPOLLIN);
                if (r >= 0)
                        r = sd_event_source_set_io_events(v->output_event_source, e & EPOLLOUT);
        }
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to set source events: %m");

        r = sd_varlink_get_timeout(v, &until);
        if (r < 0)
                return r;
        have_timeout = r > 0;

        if (have_timeout) {
                r = sd_event_source_set_time(v->time_event_source, until);
                if (r < 0)
                        return varlink_log_errno(v, r, "Failed to set source time: %m");
        }

        r = sd_event_source_set_enabled(v->time_event_source, have_timeout ? SD_EVENT_ON : SD_EVENT_OFF);
        if (r < 0)
                return varlink_log_errno(v, r, "Failed to enable event source: %m");

        return 1;
}

static int quit_callback(sd_event_source *event, void *userdata) {
        sd_varlink *v = ASSERT_PTR(userdata);

        assert(event);

        sd_varlink_flush(v);
        sd_varlink_close(v);

        return 1;
}

_public_ int sd_varlink_attach_event(sd_varlink *v, sd_event *e, int64_t priority) {
        int r;

        assert_return(v, -EINVAL);
        assert_return(!v->event, -EBUSY);

        if (e)
                v->event = sd_event_ref(e);
        else {
                r = sd_event_default(&v->event);
                if (r < 0)
                        return varlink_log_errno(v, r, "Failed to create event source: %m");
        }

        r = sd_event_add_time(v->event, &v->time_event_source, CLOCK_MONOTONIC, 0, 0, time_callback, v);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_priority(v->time_event_source, priority);
        if (r < 0)
                goto fail;

        (void) sd_event_source_set_description(v->time_event_source, "varlink-time");

        r = sd_event_add_exit(v->event, &v->quit_event_source, quit_callback, v);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_priority(v->quit_event_source, priority);
        if (r < 0)
                goto fail;

        (void) sd_event_source_set_description(v->quit_event_source, "varlink-quit");

        r = sd_event_add_io(v->event, &v->input_event_source, v->input_fd, 0, io_callback, v);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_prepare(v->input_event_source, prepare_callback);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_priority(v->input_event_source, priority);
        if (r < 0)
                goto fail;

        (void) sd_event_source_set_description(v->input_event_source, "varlink-input");

        if (v->input_fd == v->output_fd)
                v->output_event_source = sd_event_source_ref(v->input_event_source);
        else {
                r = sd_event_add_io(v->event, &v->output_event_source, v->output_fd, 0, io_callback, v);
                if (r < 0)
                        goto fail;

                r = sd_event_source_set_priority(v->output_event_source, priority);
                if (r < 0)
                        goto fail;

                (void) sd_event_source_set_description(v->output_event_source, "varlink-output");
        }

        r = sd_event_add_defer(v->event, &v->defer_event_source, defer_callback, v);
        if (r < 0)
                goto fail;

        r = sd_event_source_set_priority(v->defer_event_source, priority);
        if (r < 0)
                goto fail;

        (void) sd_event_source_set_description(v->defer_event_source, "varlink-defer");

        return 0;

fail:
        varlink_log_errno(v, r, "Failed to setup event source: %m");
        sd_varlink_detach_event(v);
        return r;
}

_public_ void sd_varlink_detach_event(sd_varlink *v) {
        if (!v)
                return;

        varlink_detach_event_sources(v);

        v->event = sd_event_unref(v->event);
}

_public_ sd_event* sd_varlink_get_event(sd_varlink *v) {
        assert_return(v, NULL);

        return v->event;
}

_public_ int sd_varlink_push_fd(sd_varlink *v, int fd) {
        int i;

        assert_return(v, -EINVAL);
        assert_return(fd >= 0, -EBADF);

        /* Takes an fd to send along with the *next* varlink message sent via this varlink connection. This
         * takes ownership of the specified fd. Use varlink_dup_fd() below to duplicate the fd first. */

        if (!v->allow_fd_passing_output)
                return -EPERM;

        if (v->n_pushed_fds >= SCM_MAX_FD) /* Kernel doesn't support more than 253 fds per message, refuse early hence */
                return -ENOBUFS;

        if (!GREEDY_REALLOC(v->pushed_fds, v->n_pushed_fds + 1))
                return -ENOMEM;

        i = (int) v->n_pushed_fds;
        v->pushed_fds[v->n_pushed_fds++] = fd;
        return i;
}

_public_ int sd_varlink_push_dup_fd(sd_varlink *v, int fd) {
        _cleanup_close_ int dp = -1;
        int r;

        assert_return(v, -EINVAL);
        assert_return(fd >= 0, -EBADF);

        /* Like varlink_push_fd() but duplicates the specified fd instead of taking possession of it */

        dp = fcntl(fd, F_DUPFD_CLOEXEC, 3);
        if (dp < 0)
                return -errno;

        r = sd_varlink_push_fd(v, dp);
        if (r < 0)
                return r;

        TAKE_FD(dp);
        return r;
}

_public_ int sd_varlink_peek_fd(sd_varlink *v, size_t i) {
        assert_return(v, -EINVAL);

        /* Returns one of the file descriptors that were received along with the current message. This does
         * not duplicate the fd nor invalidate it, it hence remains in our possession. */

        if (v->allow_fd_passing_input <= 0)
                return -EPERM;

        if (i >= v->n_input_fds)
                return -ENXIO;

        return v->input_fds[i];
}

_public_ int sd_varlink_peek_dup_fd(sd_varlink *v, size_t i) {
        int fd;

        fd = sd_varlink_peek_fd(v, i);
        if (fd < 0)
                return fd;

        return RET_NERRNO(fcntl(fd, F_DUPFD_CLOEXEC, 3));
}

_public_ int sd_varlink_take_fd(sd_varlink *v, size_t i) {
        assert_return(v, -EINVAL);

        /* Similar to varlink_peek_fd() but the file descriptor's ownership is passed to the caller, and
         * we'll invalidate the reference to it under our possession. If called twice in a row will return
         * -EBADF */

        if (v->allow_fd_passing_input <= 0)
                return -EPERM;

        if (i >= v->n_input_fds)
                return -ENXIO;

        return TAKE_FD(v->input_fds[i]);
}

_public_ int sd_varlink_get_n_fds(sd_varlink *v) {
        assert_return(v, -EINVAL);

        if (v->allow_fd_passing_input <= 0)
                return -EPERM;

        return (int) v->n_input_fds;
}

static int verify_unix_socket(sd_varlink *v) {
        assert(v);

        /* Returns:
         *    • 0 if this is an AF_UNIX socket
         *    • -ENOTSOCK if this is not a socket at all
         *    • -ENOMEDIUM if this is a socket, but not an AF_UNIX socket
         *
         * Reminder:
         *    • v->af is < 0 if we haven't checked what kind of address family the thing is yet.
         *    • v->af == AF_UNSPEC if we checked but it's not a socket
         *    • otherwise: v->af contains the address family we determined */

        if (v->af < 0) {
                /* If we have distinct input + output fds, we don't consider ourselves to be connected via a regular
                 * AF_UNIX socket. */
                if (v->input_fd != v->output_fd) {
                        v->af = AF_UNSPEC;
                        return -ENOTSOCK;
                }

                struct stat st;

                if (fstat(v->input_fd, &st) < 0)
                        return -errno;
                if (!S_ISSOCK(st.st_mode)) {
                        v->af = AF_UNSPEC;
                        return -ENOTSOCK;
                }

                v->af = socket_get_family(v->input_fd);
                if (v->af < 0)
                        return v->af;
        }

        return v->af == AF_UNIX ? 0 :
                v->af == AF_UNSPEC ? -ENOTSOCK : -ENOMEDIUM;
}

_public_ int sd_varlink_set_allow_fd_passing_input(sd_varlink *v, int b) {
        int r;

        assert_return(v, -EINVAL);

        if (v->allow_fd_passing_input >= 0 && (v->allow_fd_passing_input > 0) == !!b)
                return 0;

        r = verify_unix_socket(v);
        if (r < 0) {
                assert(v->allow_fd_passing_input <= 0);

                if (!b) {
                        v->allow_fd_passing_input = false;
                        return 0;
                }

                return r;
        }

        if (!v->server || FLAGS_SET(v->server->flags, SD_VARLINK_SERVER_FD_PASSING_INPUT_STRICT)) {
                r = setsockopt_int(v->input_fd, SOL_SOCKET, SO_PASSRIGHTS, !!b);
                if (r < 0 && !ERRNO_IS_NEG_NOT_SUPPORTED(r))
                        log_debug_errno(r, "Failed to set SO_PASSRIGHTS socket option: %m");
        }

        v->allow_fd_passing_input = !!b;
        return 1;
}

_public_ int sd_varlink_set_allow_fd_passing_output(sd_varlink *v, int b) {
        int r;

        assert_return(v, -EINVAL);

        if (v->allow_fd_passing_output == !!b)
                return 0;

        r = verify_unix_socket(v);
        if (r < 0)
                return r;

        v->allow_fd_passing_output = !!b;
        return 1;
}

_public_ int sd_varlink_set_input_sensitive(sd_varlink *v) {
        assert_return(v, -EINVAL);

        v->input_sensitive = true;
        return 0;
}

_public_ int sd_varlink_server_new(sd_varlink_server **ret, sd_varlink_server_flags_t flags) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *s = NULL;
        int r;

        assert_return(ret, -EINVAL);
        assert_return((flags & ~(SD_VARLINK_SERVER_ROOT_ONLY|
                                 SD_VARLINK_SERVER_MYSELF_ONLY|
                                 SD_VARLINK_SERVER_ACCOUNT_UID|
                                 SD_VARLINK_SERVER_INHERIT_USERDATA|
                                 SD_VARLINK_SERVER_INPUT_SENSITIVE|
                                 SD_VARLINK_SERVER_ALLOW_FD_PASSING_INPUT|
                                 SD_VARLINK_SERVER_ALLOW_FD_PASSING_OUTPUT|
                                 SD_VARLINK_SERVER_FD_PASSING_INPUT_STRICT|
                                 SD_VARLINK_SERVER_HANDLE_SIGINT|
                                 SD_VARLINK_SERVER_HANDLE_SIGTERM)) == 0, -EINVAL);

        s = new(sd_varlink_server, 1);
        if (!s)
                return log_oom_debug();

        *s = (sd_varlink_server) {
                .n_ref = 1,
                .flags = flags,
                .connections_max = sd_varlink_server_connections_max(NULL),
                .connections_per_uid_max = sd_varlink_server_connections_per_uid_max(NULL),
        };

        r = sd_varlink_server_add_interface_many(
                        s,
                        &vl_interface_io_systemd,
                        &vl_interface_org_varlink_service);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(s);
        return 0;
}

static sd_varlink_server* varlink_server_destroy(sd_varlink_server *s) {
        char *m;

        if (!s)
                return NULL;

        sd_varlink_server_shutdown(s);

        while ((m = hashmap_steal_first_key(s->methods)))
                free(m);

        hashmap_free(s->methods);
        hashmap_free(s->interfaces);
        hashmap_free(s->symbols);
        hashmap_free(s->by_uid);

        sd_event_unref(s->event);

        free(s->description);
        free(s->vendor);
        free(s->product);
        free(s->version);
        free(s->url);

        return mfree(s);
}

DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC(sd_varlink_server, sd_varlink_server, varlink_server_destroy);

_public_ int sd_varlink_server_set_info(
                sd_varlink_server *s,
                const char *vendor,
                const char *product,
                const char *version,
                const char *url) {

        assert_return(s, -EINVAL);

        _cleanup_free_ char
                *a = vendor ? strdup(vendor) : NULL,
                *b = product ? strdup(product) : NULL,
                *c = version ? strdup(version) : NULL,
                *d = url ? strdup(url) : NULL;
        if ((vendor && !a) || (product && !b) || (version && !c) || (url && !d))
                return log_oom_debug();

        free_and_replace(s->vendor, a);
        free_and_replace(s->product, b);
        free_and_replace(s->version, c);
        free_and_replace(s->url, d);

        return 0;
}

static int validate_connection(sd_varlink_server *server, const struct ucred *ucred) {
        int allowed = -1;

        assert(server);
        assert(ucred);

        if (FLAGS_SET(server->flags, SD_VARLINK_SERVER_ROOT_ONLY))
                allowed = ucred->uid == 0;

        if (FLAGS_SET(server->flags, SD_VARLINK_SERVER_MYSELF_ONLY))
                allowed = allowed > 0 || ucred->uid == getuid();

        if (allowed == 0) { /* Allow access when it is explicitly allowed or when neither
                             * VARLINK_SERVER_ROOT_ONLY nor VARLINK_SERVER_MYSELF_ONLY are specified. */
                varlink_server_log(server, "Unprivileged client attempted connection, refusing.");
                return 0;
        }

        if (server->n_connections >= server->connections_max) {
                varlink_server_log(server, "Connection limit of %u reached, refusing.", server->connections_max);
                return 0;
        }

        if (FLAGS_SET(server->flags, SD_VARLINK_SERVER_ACCOUNT_UID)) {
                unsigned c;

                if (!uid_is_valid(ucred->uid)) {
                        varlink_server_log(server, "Client with invalid UID attempted connection, refusing.");
                        return 0;
                }

                c = PTR_TO_UINT(hashmap_get(server->by_uid, UID_TO_PTR(ucred->uid)));
                if (c >= server->connections_per_uid_max) {
                        varlink_server_log(server, "Per-UID connection limit of %u for '" UID_FMT "' reached, refusing.",
                                           server->connections_per_uid_max, ucred->uid);
                        return 0;
                }
        }

        return 1;
}

static int count_connection(sd_varlink_server *server, const struct ucred *ucred) {
        unsigned c;
        int r;

        assert(server);
        assert(ucred);

        server->n_connections++;

        if (FLAGS_SET(server->flags, SD_VARLINK_SERVER_ACCOUNT_UID)) {
                assert(uid_is_valid(ucred->uid));

                r = hashmap_ensure_allocated(&server->by_uid, NULL);
                if (r < 0)
                        return varlink_server_log_errno(server, r, "Failed to allocate UID hash table: %m");

                c = PTR_TO_UINT(hashmap_get(server->by_uid, UID_TO_PTR(ucred->uid)));

                varlink_server_log(server, "Connections of user " UID_FMT ": %u (of %u max)",
                                   ucred->uid, c, server->connections_per_uid_max);

                r = hashmap_replace(server->by_uid, UID_TO_PTR(ucred->uid), UINT_TO_PTR(c + 1));
                if (r < 0)
                        return varlink_server_log_errno(server, r, "Failed to increment counter in UID hash table: %m");
        }

        return 0;
}

_public_ int sd_varlink_server_add_connection_pair(
                sd_varlink_server *server,
                int input_fd,
                int output_fd,
                const struct ucred *override_ucred,
                sd_varlink **ret) {

        _cleanup_(sd_varlink_unrefp) sd_varlink *v = NULL;
        struct ucred ucred = UCRED_INVALID;
        bool ucred_acquired;
        int r;

        assert_return(server, -EINVAL);
        assert_return(input_fd >= 0, -EBADF);
        assert_return(output_fd >= 0, -EBADF);

        if ((server->flags & (SD_VARLINK_SERVER_ROOT_ONLY|SD_VARLINK_SERVER_ACCOUNT_UID)) != 0) {

                if (override_ucred)
                        ucred = *override_ucred;
                else {
                        if (input_fd != output_fd)
                                return varlink_server_log_errno(server, SYNTHETIC_ERRNO(EOPNOTSUPP), "Cannot determine peer identity of connection with separate input/output, refusing.");

                        r = getpeercred(input_fd, &ucred);
                        if (r < 0)
                                return varlink_server_log_errno(server, r, "Failed to acquire peer credentials of incoming socket, refusing: %m");
                }

                ucred_acquired = true;

                r = validate_connection(server, &ucred);
                if (r < 0)
                        return r;
                if (r == 0)
                        return -EPERM;
        } else
                ucred_acquired = false;

        r = varlink_new(&v);
        if (r < 0)
                return varlink_server_log_errno(server, r, "Failed to allocate connection object: %m");

        r = count_connection(server, &ucred);
        if (r < 0)
                return r;

        /* Link up the server and the connection, and take reference in both directions. Note that the
         * reference on the connection is left dangling. It will be dropped when the connection is closed,
         * which happens in varlink_close(), including in the event loop quit callback. */
        v->server = sd_varlink_server_ref(server);
        sd_varlink_ref(v);

        v->input_fd = input_fd;
        v->output_fd = output_fd;
        if (server->flags & SD_VARLINK_SERVER_INHERIT_USERDATA)
                v->userdata = server->userdata;

        if (ucred_acquired) {
                v->ucred = ucred;
                v->ucred_acquired = true;
        }

        _cleanup_free_ char *desc = NULL;
        if (asprintf(&desc, "%s-%i-%i", varlink_server_description(server), input_fd, output_fd) >= 0)
                v->description = TAKE_PTR(desc);

        (void) sd_varlink_set_allow_fd_passing_input(v, FLAGS_SET(server->flags, SD_VARLINK_SERVER_ALLOW_FD_PASSING_INPUT));
        (void) sd_varlink_set_allow_fd_passing_output(v, FLAGS_SET(server->flags, SD_VARLINK_SERVER_ALLOW_FD_PASSING_OUTPUT));

        varlink_set_state(v, VARLINK_IDLE_SERVER);

        if (server->event) {
                r = sd_varlink_attach_event(v, server->event, server->event_priority);
                if (r < 0) {
                        varlink_log_errno(v, r, "Failed to attach new connection: %m");
                        TAKE_FD(v->input_fd); /* take the fd out of the connection again */
                        TAKE_FD(v->output_fd);
                        sd_varlink_close(v);
                        return r;
                }
        }

        if (ret)
                *ret = v;

        return 0;
}

_public_ int sd_varlink_server_add_connection(sd_varlink_server *server, int fd, sd_varlink **ret) {
        return sd_varlink_server_add_connection_pair(server, fd, fd, /* override_ucred= */ NULL, ret);
}

VarlinkServerSocket* varlink_server_socket_free(VarlinkServerSocket *ss) {
        if (!ss)
                return NULL;

        free(ss->address);
        return mfree(ss);
}

static int connect_callback(sd_event_source *source, int fd, uint32_t revents, void *userdata) {
        VarlinkServerSocket *ss = ASSERT_PTR(userdata);
        _cleanup_close_ int cfd = -EBADF;
        sd_varlink *v = NULL;
        int r;

        assert(source);

        varlink_server_log(ss->server, "New incoming connection.");

        cfd = accept4(fd, NULL, NULL, SOCK_NONBLOCK|SOCK_CLOEXEC);
        if (cfd < 0) {
                if (ERRNO_IS_ACCEPT_AGAIN(errno))
                        return 0;

                return varlink_server_log_errno(ss->server, errno, "Failed to accept incoming socket: %m");
        }

        r = sd_varlink_server_add_connection(ss->server, cfd, &v);
        if (r < 0)
                return 0;

        TAKE_FD(cfd);

        if (FLAGS_SET(ss->server->flags, SD_VARLINK_SERVER_INPUT_SENSITIVE))
                sd_varlink_set_input_sensitive(v);

        if (ss->server->connect_callback) {
                r = ss->server->connect_callback(ss->server, v, ss->server->userdata);
                if (r < 0) {
                        varlink_log_errno(v, r, "Connection callback returned error, disconnecting client: %m");
                        sd_varlink_close(v);
                        return 0;
                }
        }

        return 0;
}

static int varlink_server_create_listen_fd_socket(sd_varlink_server *s, int fd, VarlinkServerSocket **ret_ss) {
        _cleanup_(varlink_server_socket_freep) VarlinkServerSocket *ss = NULL;
        int r;

        assert(s);
        assert(fd >= 0);
        assert(ret_ss);

        ss = new(VarlinkServerSocket, 1);
        if (!ss)
                return log_oom_debug();

        *ss = (VarlinkServerSocket) {
                .server = s,
                .fd = fd,
        };

        if (s->event) {
                r = sd_event_add_io(s->event, &ss->event_source, fd, EPOLLIN, connect_callback, ss);
                if (r < 0)
                        return r;

                r = sd_event_source_set_priority(ss->event_source, s->event_priority);
                if (r < 0)
                        return r;
        }

        *ret_ss = TAKE_PTR(ss);
        return 0;
}

_public_ int sd_varlink_server_listen_fd(sd_varlink_server *s, int fd) {
        _cleanup_(varlink_server_socket_freep) VarlinkServerSocket *ss = NULL;
        int r;

        assert_return(s, -EINVAL);
        assert_return(fd >= 0, -EBADF);

        r = fd_nonblock(fd, true);
        if (r < 0)
                return r;

        r = fd_cloexec(fd, true);
        if (r < 0)
                return r;

        /* If fd passing is disabled on server, and SD_VARLINK_SERVER_FD_PASSING_INPUT_STRICT flag is set,
         * turn off SO_PASSRIGHTS immediately on listening socket. The conditionalization behind a flag
         * is needed to retain backwards compat, where implementations would register a connection callback
         * to enable fd passing after accept(), which might race with clients wrt SO_PASSRIGHTS state. */
        if (FLAGS_SET(s->flags, SD_VARLINK_SERVER_FD_PASSING_INPUT_STRICT))
                (void) setsockopt_int(fd, SOL_SOCKET, SO_PASSRIGHTS, FLAGS_SET(s->flags, SD_VARLINK_SERVER_ALLOW_FD_PASSING_INPUT));

        r = varlink_server_create_listen_fd_socket(s, fd, &ss);
        if (r < 0)
                return r;

        LIST_PREPEND(sockets, s->sockets, TAKE_PTR(ss));
        return 0;
}

_public_ int sd_varlink_server_listen_address(sd_varlink_server *s, const char *address, mode_t m) {
        _cleanup_(varlink_server_socket_freep) VarlinkServerSocket *ss = NULL;
        union sockaddr_union sockaddr;
        socklen_t sockaddr_len;
        _cleanup_close_ int fd = -EBADF;
        int r;

        assert_return(s, -EINVAL);
        assert_return(address, -EINVAL);
        assert_return((m & ~(0777|SD_VARLINK_SERVER_MODE_MKDIR_0755)) == 0, -EINVAL);

        /* Validate that the definition of our flag doesn't collide with the official mode_t bits. Thankfully
         * the bit values of mode_t flags are fairly well established (POSIX and all), hence we should be
         * safe here. */
        assert_cc(((S_IFMT|07777) & SD_VARLINK_SERVER_MODE_MKDIR_0755) == 0);

        if (FLAGS_SET(m, SD_VARLINK_SERVER_MODE_MKDIR_0755) && path_is_absolute(address)) {
                r = mkdir_parents(address, 0755);
                if (r < 0)
                        return r;
        }

        r = sockaddr_un_set_path(&sockaddr.un, address);
        if (r < 0)
                return r;
        sockaddr_len = r;

        fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (fd < 0)
                return -errno;

        fd = fd_move_above_stdio(fd);

        /* See the comment in sd_varlink_server_listen_fd() */
        if (FLAGS_SET(s->flags, SD_VARLINK_SERVER_FD_PASSING_INPUT_STRICT))
                (void) setsockopt_int(fd, SOL_SOCKET, SO_PASSRIGHTS, FLAGS_SET(s->flags, SD_VARLINK_SERVER_ALLOW_FD_PASSING_INPUT));

        (void) sockaddr_un_unlink(&sockaddr.un);

        WITH_UMASK(~m & 0777)
                r = RET_NERRNO(bind(fd, &sockaddr.sa, sockaddr_len));
        if (r < 0)
                return r;

        if (listen(fd, SOMAXCONN_DELUXE) < 0)
                return -errno;

        r = varlink_server_create_listen_fd_socket(s, fd, &ss);
        if (r < 0)
                return r;

        r = free_and_strdup(&ss->address, address);
        if (r < 0)
                return r;

        LIST_PREPEND(sockets, s->sockets, TAKE_PTR(ss));
        TAKE_FD(fd);
        return 0;
}

_public_ int sd_varlink_server_add_connection_stdio(sd_varlink_server *s, sd_varlink **ret) {
        _cleanup_close_ int input_fd = -EBADF, output_fd = -EBADF;
        int r;

        assert_return(s, -EINVAL);

        input_fd = fcntl(STDIN_FILENO, F_DUPFD_CLOEXEC, 3);
        if (input_fd < 0)
                return -errno;

        output_fd = fcntl(STDOUT_FILENO, F_DUPFD_CLOEXEC, 3);
        if (output_fd < 0)
                return -errno;

        r = rearrange_stdio(-EBADF, -EBADF, STDERR_FILENO);
        if (r < 0)
                return r;

        r = fd_nonblock(input_fd, true);
        if (r < 0)
                return r;

        r = fd_nonblock(output_fd, true);
        if (r < 0)
                return r;

        struct stat input_st;
        if (fstat(input_fd, &input_st) < 0)
                return -errno;

        struct stat output_st;
        if (fstat(output_fd, &output_st) < 0)
                return -errno;

        /* If stdin/stdout are both pipes and have the same owning uid/gid then let's synthesize a "struct
         * ucred" from the owning UID/GID, since we got them passed in with such ownership. We'll not fill in
         * the PID however, since there's no way to know which process created a pipe. */
        struct ucred ucred, *pucred;
        if (S_ISFIFO(input_st.st_mode) &&
            S_ISFIFO(output_st.st_mode) &&
            input_st.st_uid == output_st.st_uid &&
            input_st.st_gid == output_st.st_gid) {
                ucred = (struct ucred) {
                        .uid = input_st.st_uid,
                        .gid = input_st.st_gid,
                };
                pucred = &ucred;
        } else
                pucred = NULL;

        r = sd_varlink_server_add_connection_pair(s, input_fd, output_fd, pucred, ret);
        if (r < 0)
                return r;

        TAKE_FD(input_fd);
        TAKE_FD(output_fd);

        return 0;
}

_public_ int sd_varlink_server_listen_name(sd_varlink_server *s, const char *name) {
        _cleanup_strv_free_ char **names = NULL;
        int r, m, n = 0;

        assert_return(s, -EINVAL);
        assert_return(name, -EINVAL);

        /* Adds all passed fds marked as "name" to our varlink server. These fds can either refer to a
         * listening socket or to a connection socket.
         *
         * See https://varlink.org/#activation for the environment variables this is backed by and the
         * recommended "varlink" identifier in $LISTEN_FDNAMES. */

        m = sd_listen_fds_with_names(/* unset_environment= */ false, &names);
        if (m < 0)
                return m;

        for (int i = 0; i < m; i++) {
                int b, fd;
                socklen_t l = sizeof(b);

                if (!streq(names[i], name))
                        continue;

                fd = SD_LISTEN_FDS_START + i;

                if (getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &b, &l) < 0)
                        return -errno;

                assert(l == sizeof(b));

                if (b) /* Listening socket? */
                        r = sd_varlink_server_listen_fd(s, fd);
                else /* Otherwise assume connection socket */
                        r = sd_varlink_server_add_connection(s, fd, NULL);
                if (r < 0)
                        return r;

                n++;
        }

        return n;
}

_public_ int sd_varlink_server_listen_auto(sd_varlink_server *s) {
        int r, n;

        assert_return(s, -EINVAL);

        n = sd_varlink_server_listen_name(s, "varlink");
        if (n < 0)
                return n;

        /* Let's listen on an explicitly specified address */
        const char *e = secure_getenv("SYSTEMD_VARLINK_LISTEN");
        if (e) {
                if (streq(e, "-"))
                        r = sd_varlink_server_add_connection_stdio(s, /* ret= */ NULL);
                else
                        r = sd_varlink_server_listen_address(s, e, FLAGS_SET(s->flags, SD_VARLINK_SERVER_ROOT_ONLY) ? 0600 : 0666);
                if (r < 0)
                        return r;

                n++;
        }

        return n;
}

_public_ void* sd_varlink_server_set_userdata(sd_varlink_server *s, void *userdata) {
        void *ret;

        assert_return(s, NULL);

        ret = s->userdata;
        s->userdata = userdata;

        return ret;
}

_public_ void* sd_varlink_server_get_userdata(sd_varlink_server *s) {
        assert_return(s, NULL);

        return s->userdata;
}

_public_ int sd_varlink_server_loop_auto(sd_varlink_server *server) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        int r;

        assert_return(server, -EINVAL);
        assert_return(!server->event, -EBUSY);

        /* Runs a sd_varlink service event loop populated with a passed fd. Exits on the last connection. */

        r = sd_event_new(&event);
        if (r < 0)
                return r;

        r = sd_varlink_server_set_exit_on_idle(server, true);
        if (r < 0)
                return r;

        if (FLAGS_SET(server->flags, SD_VARLINK_SERVER_HANDLE_SIGINT)) {
                r = sd_event_add_signal(event, /* ret= */ NULL, SIGINT|SD_EVENT_SIGNAL_PROCMASK, /* callback= */ NULL, /* userdata= */ NULL);
                if (r < 0)
                        return r;
        }

        if (FLAGS_SET(server->flags, SD_VARLINK_SERVER_HANDLE_SIGTERM)) {
                r = sd_event_add_signal(event, /* ret= */ NULL, SIGTERM|SD_EVENT_SIGNAL_PROCMASK, /* callback= */ NULL, /* userdata= */ NULL);
                if (r < 0)
                        return r;
        }

        r = sd_varlink_server_attach_event(server, event, 0);
        if (r < 0)
                return r;

        r = sd_varlink_server_listen_auto(server);
        if (r < 0)
                return r;

        return sd_event_loop(event);
}

static VarlinkServerSocket* varlink_server_socket_destroy(VarlinkServerSocket *ss) {
        if (!ss)
                return NULL;

        if (ss->server)
                LIST_REMOVE(sockets, ss->server->sockets, ss);

        sd_event_source_disable_unref(ss->event_source);

        free(ss->address);
        safe_close(ss->fd);

        return mfree(ss);
}

_public_ int sd_varlink_server_shutdown(sd_varlink_server *s) {
        assert_return(s, -EINVAL);

        while (s->sockets)
                varlink_server_socket_destroy(s->sockets);

        return 0;
}

static void varlink_server_test_exit_on_idle(sd_varlink_server *s) {
        assert(s);

        if (s->exit_on_idle && s->event && s->n_connections == 0)
                (void) sd_event_exit(s->event, 0);
}

_public_ int sd_varlink_server_set_exit_on_idle(sd_varlink_server *s, int b) {
        assert_return(s, -EINVAL);

        s->exit_on_idle = b;
        varlink_server_test_exit_on_idle(s);
        return 0;
}

int varlink_server_add_socket_event_source(sd_varlink_server *s, VarlinkServerSocket *ss, int64_t priority) {
        _cleanup_(sd_event_source_unrefp) sd_event_source *es = NULL;
        int r;

        assert(s);
        assert(s->event);
        assert(ss);
        assert(ss->fd >= 0);
        assert(!ss->event_source);

        r = sd_event_add_io(s->event, &es, ss->fd, EPOLLIN, connect_callback, ss);
        if (r < 0)
                return r;

        r = sd_event_source_set_priority(es, priority);
        if (r < 0)
                return r;

        ss->event_source = TAKE_PTR(es);
        return 0;
}

_public_ int sd_varlink_server_attach_event(sd_varlink_server *s, sd_event *e, int64_t priority) {
        int r;

        assert_return(s, -EINVAL);
        assert_return(!s->event, -EBUSY);

        if (e)
                s->event = sd_event_ref(e);
        else {
                r = sd_event_default(&s->event);
                if (r < 0)
                        return r;
        }

        LIST_FOREACH(sockets, ss, s->sockets) {
                r = varlink_server_add_socket_event_source(s, ss, priority);
                if (r < 0)
                        goto fail;
        }

        s->event_priority = priority;
        return 0;

fail:
        sd_varlink_server_detach_event(s);
        return r;
}

_public_ int sd_varlink_server_detach_event(sd_varlink_server *s) {
        assert_return(s, -EINVAL);

        LIST_FOREACH(sockets, ss, s->sockets)
                ss->event_source = sd_event_source_disable_unref(ss->event_source);

        s->event = sd_event_unref(s->event);
        return 0;
}

_public_ sd_event* sd_varlink_server_get_event(sd_varlink_server *s) {
        assert_return(s, NULL);

        return s->event;
}

static bool varlink_symbol_in_interface(const char *method, const char *interface) {
        const char *p;

        assert(method);
        assert(interface);

        p = startswith(method, interface);
        if (!p)
                return false;

        if (*p != '.')
                return false;

        return !strchr(p+1, '.');
}

_public_ int sd_varlink_server_bind_method(sd_varlink_server *s, const char *method, sd_varlink_method_t callback) {
        _cleanup_free_ char *m = NULL;
        int r;

        assert_return(s, -EINVAL);
        assert_return(method, -EINVAL);
        assert_return(callback, -EINVAL);

        if (varlink_symbol_in_interface(method, "org.varlink.service") ||
            varlink_symbol_in_interface(method, "io.systemd"))
                return varlink_server_log_errno(s, SYNTHETIC_ERRNO(EEXIST), "Cannot bind server to '%s'.", method);

        m = strdup(method);
        if (!m)
                return log_oom_debug();

        r = hashmap_ensure_put(&s->methods, &string_hash_ops, m, callback);
        if (r == -ENOMEM)
                return log_oom_debug();
        if (r < 0)
                return varlink_server_log_errno(s, r, "Failed to register callback: %m");
        if (r > 0)
                TAKE_PTR(m);

        return 0;
}

_public_ int sd_varlink_server_bind_method_many_internal(sd_varlink_server *s, ...) {
        va_list ap;
        int r = 0;

        assert_return(s, -EINVAL);

        va_start(ap, s);
        for (;;) {
                sd_varlink_method_t callback;
                const char *method;

                method = va_arg(ap, const char *);
                if (!method)
                        break;

                callback = va_arg(ap, sd_varlink_method_t);

                r = sd_varlink_server_bind_method(s, method, callback);
                if (r < 0)
                        break;
        }
        va_end(ap);

        return r;
}

_public_ int sd_varlink_server_bind_connect(sd_varlink_server *s, sd_varlink_connect_t connect) {
        assert_return(s, -EINVAL);

        if (connect && s->connect_callback && connect != s->connect_callback)
                return varlink_server_log_errno(s, SYNTHETIC_ERRNO(EBUSY), "A different callback was already set.");

        s->connect_callback = connect;
        return 0;
}

_public_ int sd_varlink_server_bind_disconnect(sd_varlink_server *s, sd_varlink_disconnect_t disconnect) {
        assert_return(s, -EINVAL);

        if (disconnect && s->disconnect_callback && disconnect != s->disconnect_callback)
                return varlink_server_log_errno(s, SYNTHETIC_ERRNO(EBUSY), "A different callback was already set.");

        s->disconnect_callback = disconnect;
        return 0;
}

_public_ int sd_varlink_server_add_interface(sd_varlink_server *s, const sd_varlink_interface *interface) {
        int r;

        assert_return(s, -EINVAL);
        assert_return(interface, -EINVAL);
        assert_return(interface->name, -EINVAL);

        if (hashmap_contains(s->interfaces, interface->name))
                return varlink_server_log_errno(s, SYNTHETIC_ERRNO(EEXIST), "Duplicate registration of interface '%s'.", interface->name);

        r = hashmap_ensure_put(&s->interfaces, &string_hash_ops, interface->name, (void*) interface);
        if (r < 0)
                return r;

        for (const sd_varlink_symbol *const*symbol = interface->symbols; *symbol; symbol++) {
                _cleanup_free_ char *j = NULL;

                /* We only ever want to validate method calls/replies and errors against the interface
                 * definitions, hence don't bother with the type symbols */
                if (!IN_SET((*symbol)->symbol_type, SD_VARLINK_METHOD, SD_VARLINK_ERROR))
                        continue;

                j = strjoin(interface->name, ".", (*symbol)->name);
                if (!j)
                        return -ENOMEM;

                r = hashmap_ensure_put(&s->symbols, &string_hash_ops_free, j, (void*) *symbol);
                if (r < 0)
                        return r;

                TAKE_PTR(j);
        }

        return 0;
}

_public_ int sd_varlink_server_add_interface_many_internal(sd_varlink_server *s, ...) {
        va_list ap;
        int r = 0;

        assert_return(s, -EINVAL);

        va_start(ap, s);
        for (;;) {
                const sd_varlink_interface *interface = va_arg(ap, const sd_varlink_interface*);
                if (!interface)
                        break;

                r = sd_varlink_server_add_interface(s, interface);
                if (r < 0)
                        break;
        }
        va_end(ap);

        return r;
}

_public_ unsigned sd_varlink_server_connections_max(sd_varlink_server *s) {

        /* If a server is specified, return the setting for that server, otherwise the default value */
        if (s)
                return s->connections_max;

        int dts = getdtablesize();
        assert_se(dts > 0);

        /* Make sure we never use up more than ¾th of RLIMIT_NOFILE for IPC */
        return MIN(VARLINK_DEFAULT_CONNECTIONS_MAX, (unsigned) dts / 4 * 3);
}

_public_ unsigned sd_varlink_server_connections_per_uid_max(sd_varlink_server *s) {
        unsigned m;

        if (s)
                return s->connections_per_uid_max;

        /* Make sure to never use up more than ¾th of available connections for a single user */
        m = sd_varlink_server_connections_max(NULL);
        if (VARLINK_DEFAULT_CONNECTIONS_PER_UID_MAX > m)
                return m / 4 * 3;

        return VARLINK_DEFAULT_CONNECTIONS_PER_UID_MAX;
}

_public_ int sd_varlink_server_set_connections_per_uid_max(sd_varlink_server *s, unsigned m) {
        assert_return(s, -EINVAL);
        assert_return(m > 0, -EINVAL);

        s->connections_per_uid_max = m;
        return 0;
}

_public_ int sd_varlink_server_set_connections_max(sd_varlink_server *s, unsigned m) {
        assert_return(s, -EINVAL);
        assert_return(m > 0, -EINVAL);

        s->connections_max = m;
        return 0;
}

_public_ unsigned sd_varlink_server_current_connections(sd_varlink_server *s) {

        if (!s) /* Unallocated servers have zero connections */
                return 0;

        return s->n_connections;
}

_public_ int sd_varlink_server_set_description(sd_varlink_server *s, const char *description) {
        assert_return(s, -EINVAL);

        return free_and_strdup(&s->description, description);
}

_public_ int sd_varlink_invocation(sd_varlink_invocation_flags_t flags) {
        _cleanup_strv_free_ char **names = NULL;
        int r, b;
        socklen_t l = sizeof(b);

        /* Returns true if this is a "pure" varlink server invocation, i.e. with one fd passed. */

        const char *e = secure_getenv("SYSTEMD_VARLINK_LISTEN"); /* Permit an explicit override */
        if (e)
                return true;

        r = sd_listen_fds_with_names(/* unset_environment= */ false, &names);
        if (r < 0)
                return r;
        if (r == 0)
                return false;
        if (r > 1)
                return -ETOOMANYREFS;

        if (!strv_equal(names, STRV_MAKE("varlink")))
                return false;

        if (FLAGS_SET(flags, SD_VARLINK_ALLOW_LISTEN|SD_VARLINK_ALLOW_ACCEPT)) /* Both flags set? Then allow everything */
                return true;

        if ((flags & (SD_VARLINK_ALLOW_LISTEN|SD_VARLINK_ALLOW_ACCEPT)) == 0) /* Neither is set, then fail */
                return -EISCONN;

        if (getsockopt(SD_LISTEN_FDS_START, SOL_SOCKET, SO_ACCEPTCONN, &b, &l) < 0)
                return -errno;

        assert(l == sizeof(b));

        if (!FLAGS_SET(flags, b ? SD_VARLINK_ALLOW_LISTEN : SD_VARLINK_ALLOW_ACCEPT))
                return -EISCONN;

        return true;
}

_public_ int sd_varlink_error_to_errno(const char *error, sd_json_variant *parameters) {
        static const struct {
                const char *error;
                int value;
        } table[] = {
                { SD_VARLINK_ERROR_DISCONNECTED,           -ECONNRESET    },
                { SD_VARLINK_ERROR_TIMEOUT,                -ETIMEDOUT     },
                { SD_VARLINK_ERROR_PROTOCOL,               -EPROTO        },
                { SD_VARLINK_ERROR_INTERFACE_NOT_FOUND,    -EADDRNOTAVAIL },
                { SD_VARLINK_ERROR_METHOD_NOT_FOUND,       -ENXIO         },
                { SD_VARLINK_ERROR_METHOD_NOT_IMPLEMENTED, -ENOTTY        },
                { SD_VARLINK_ERROR_INVALID_PARAMETER,      -EINVAL        },
                { SD_VARLINK_ERROR_PERMISSION_DENIED,      -EACCES        },
                { SD_VARLINK_ERROR_EXPECTED_MORE,          -EBADE         },
        };

        int r;

        if (!error)
                return 0;

        FOREACH_ELEMENT(t, table)
                if (streq(error, t->error))
                        return t->value;

        /* This following tries to reverse the operation sd_varlink_error_errno() applies to turn errnos into
         * varlink errors */
        if (!streq(error, SD_VARLINK_ERROR_SYSTEM))
                return -EBADR;

        if (!parameters)
                return -EBADR;

        /* If an origin is set, check if it's Linux, otherwise don't translate */
        sd_json_variant *e = sd_json_variant_by_key(parameters, "origin");
        if (e && (!sd_json_variant_is_string(e) ||
                  !streq(sd_json_variant_string(e), "linux")))
                return -EBADR;

        /* If a name is specified, go by name */
        e = sd_json_variant_by_key(parameters, "errnoName");
        if (e) {
                if (!sd_json_variant_is_string(e))
                        return -EBADR;

                r = errno_from_name(sd_json_variant_string(e));
                if (r < 0)
                        return -EBADR;

                assert(r > 0);
                return -r;
        }

        /* Finally, use the provided error number, if there is one */
        e = sd_json_variant_by_key(parameters, "errno");
        if (!e)
                return -EBADR;
        if (!sd_json_variant_is_integer(e))
                return -EBADR;

        int64_t i = sd_json_variant_integer(e);
        if (i <= 0 || i > ERRNO_MAX)
                return -EBADR;

        return (int) -i;
}

_public_ int sd_varlink_error_is_invalid_parameter(const char *error, sd_json_variant *parameter, const char *name) {

        /* Returns true if the specified error result is an invalid parameter error for the parameter 'name' */

        if (!streq_ptr(error, SD_VARLINK_ERROR_INVALID_PARAMETER))
                return false;

        if (!name)
                return true;

        if (!sd_json_variant_is_object(parameter))
                return false;

        sd_json_variant *e = sd_json_variant_by_key(parameter, "parameter");
        if (!e || !sd_json_variant_is_string(e))
                return false;

        return streq(sd_json_variant_string(e), name);
}
