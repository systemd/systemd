/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/socket.h>
#include <unistd.h>

#include "sd-future.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "hashmap.h"
#include "io-util.h"
#include "iovec-util.h"
#include "log.h"
#include "machine.h"
#include "machined.h"
#include "machined-ssh-agent.h"
#include "mkdir.h"
#include "path-lookup.h"
#include "socket-util.h"
#include "ssh-util.h"
#include "string-util.h"
#include "umask-util.h"
#include "unaligned.h"

/* PROTOCOL.agent in the OpenSSH sources defines the message types. */
#define SSH_AGENT_FAILURE              5
#define SSH_AGENTC_REQUEST_IDENTITIES 11
#define SSH_AGENT_IDENTITIES_ANSWER   12
#define SSH_AGENTC_SIGN_REQUEST       13
#define SSH_AGENT_SIGN_RESPONSE       14

#define MAX_AGENT_MESSAGE_SIZE (256U * 1024U)

/* The ssh_config drop-in of systemd-ssh-generator sets IdentityAgent= of "machine/<name>" and
 * "machine%<name>" hosts to a path in this directory. The path is the directory followed by the host
 * name. */
#define SSH_AGENT_DIRECTORY "systemd/ssh-agent"

typedef struct SshAgent {
        Manager *manager;
        char *machine_name;
        int listen_fd;
} SshAgent;

typedef struct SshAgentConnection {
        SshAgent *agent;
        int fd;
} SshAgentConnection;

static SshAgent* ssh_agent_free(SshAgent *a) {
        if (!a)
                return NULL;

        safe_close(a->listen_fd);
        free(a->machine_name);
        return mfree(a);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(SshAgent*, ssh_agent_free);

static void ssh_agent_destroy(void *userdata) {
        ssh_agent_free(userdata);
}

static SshAgentConnection* ssh_agent_connection_free(SshAgentConnection *c) {
        if (!c)
                return NULL;

        safe_close(c->fd);
        return mfree(c);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(SshAgentConnection*, ssh_agent_connection_free);

static void ssh_agent_connection_destroy(void *userdata) {
        ssh_agent_connection_free(userdata);
}

static int send_reply(SshAgentConnection *c, const struct iovec *body) {
        _cleanup_(iovec_done) struct iovec reply = {};
        int r;

        assert(c);
        assert(iovec_is_valid(body));

        r = ssh_wire_append_string(&reply, body);
        if (r < 0)
                return r;

        /* send() raises SIGPIPE when the client has already closed the connection. MSG_NOSIGNAL makes
         * send() fail with EPIPE instead. */
        return loop_send(c->fd, reply.iov_base, reply.iov_len, MSG_NOSIGNAL);
}

static int send_failure(SshAgentConnection *c) {
        assert(c);

        return send_reply(c, &IOVEC_MAKE_BYTE(SSH_AGENT_FAILURE));
}

/* Returns 0 if the machine is gone, has no key pair, or its key pair can't be loaded. */
static int ssh_agent_load_key(SshAgent *a, OpenSSHKey **ret) {
        Machine *machine;
        int r;

        assert(a);
        assert(ret);

        /* A connection can stay open after the machine is removed, so look the machine up again for every
         * request. */
        machine = hashmap_get(a->manager->machines, a->machine_name);
        if (!machine || !machine->ssh_private_key_path) {
                *ret = NULL;
                return 0;
        }

        _cleanup_free_ char *pub_path = strjoin(machine->ssh_private_key_path, ".pub");
        if (!pub_path)
                return -ENOMEM;

        r = openssh_key_load(machine->ssh_private_key_path, pub_path, ret);
        if (r < 0) {
                log_debug_errno(r, "ssh-agent: Failed to load SSH key pair of machine %s, ignoring: %m", a->machine_name);
                *ret = NULL;
                return 0;
        }

        return 1;
}

/* See section 4.4 of PROTOCOL.agent for the format of the request and the reply. */
static int handle_request_identities(SshAgentConnection *c) {
        _cleanup_(openssh_key_freep) OpenSSHKey *k = NULL;
        _cleanup_(iovec_done) struct iovec body = {};
        int r;

        assert(c);

        r = ssh_agent_load_key(c->agent, &k);
        if (r < 0)
                return r;

        if (!iovec_append(&body, &IOVEC_MAKE_BYTE(SSH_AGENT_IDENTITIES_ANSWER)))
                return -ENOMEM;

        r = ssh_wire_append_u32(&body, k ? 1 : 0);
        if (r < 0)
                return r;

        if (k) {
                _cleanup_free_ char *comment = strjoin("machine/", c->agent->machine_name);
                if (!comment)
                        return -ENOMEM;

                r = ssh_wire_append_string(&body, &k->pubkey_blob);
                if (r < 0)
                        return r;

                r = ssh_wire_append_string(&body, &IOVEC_MAKE_STRING(comment));
                if (r < 0)
                        return r;
        }

        return send_reply(c, &body);
}

/* See section 4.5.1 of PROTOCOL.agent for the format of the request and the reply. A failed request gets
 * the reply SSH_AGENT_FAILURE, and the connection stays open. The client can send another request on
 * the same connection. */
static int handle_sign_request(SshAgentConnection *c, struct iovec *payload) {
        _cleanup_(openssh_key_freep) OpenSSHKey *k = NULL;
        _cleanup_(iovec_done) struct iovec sig = {}, body = {};
        struct iovec blob, data;
        uint32_t flags;
        int r;

        assert(c);
        assert(payload);

        r = ssh_wire_read_string(payload, &blob);
        if (r < 0)
                return send_failure(c);

        r = ssh_wire_read_string(payload, &data);
        if (r < 0)
                return send_failure(c);

        r = ssh_wire_read_u32(payload, &flags);
        if (r < 0)
                return send_failure(c);

        r = ssh_agent_load_key(c->agent, &k);
        if (r < 0)
                return r;
        if (r == 0 || !iovec_equal(&k->pubkey_blob, &blob)) {
                log_debug("ssh-agent: Sign request for machine %s with an unknown key.", c->agent->machine_name);
                return send_failure(c);
        }

        r = openssh_key_sign(k, flags, &data, &sig);
        if (r < 0) {
                log_debug_errno(r, "ssh-agent: Failed to sign for machine %s: %m", c->agent->machine_name);
                return send_failure(c);
        }

        if (!iovec_append(&body, &IOVEC_MAKE_BYTE(SSH_AGENT_SIGN_RESPONSE)))
                return -ENOMEM;

        r = ssh_wire_append_string(&body, &sig);
        if (r < 0)
                return r;

        return send_reply(c, &body);
}

static int connection_dispatch_message(SshAgentConnection *c, const struct iovec *msg) {
        assert(c);
        assert(iovec_is_set(msg));

        uint8_t type = *(const uint8_t*) msg->iov_base;
        struct iovec payload = IOVEC_SHIFT(msg, 1);

        switch (type) {
        case SSH_AGENTC_REQUEST_IDENTITIES:
                return handle_request_identities(c);
        case SSH_AGENTC_SIGN_REQUEST:
                return handle_sign_request(c, &payload);
        default:
                log_debug("ssh-agent: unsupported message type %u, replying FAILURE", type);
                return send_failure(c);
        }
}

static int read_message(SshAgentConnection *c, struct iovec *ret) {
        uint8_t header[sizeof(uint32_t)];
        ssize_t n;
        int r;

        assert(c);
        assert(ret);

        n = loop_read(c->fd, header, sizeof(header), /* do_poll= */ true);
        if (n < 0)
                return (int) n;
        if (n == 0)
                return 0;
        if ((size_t) n != sizeof(header))
                return -EIO;

        uint32_t len = unaligned_read_be32(header);
        if (len == 0 || len > MAX_AGENT_MESSAGE_SIZE)
                return -EBADMSG;

        _cleanup_free_ void *buf = malloc(len);
        if (!buf)
                return -ENOMEM;

        r = loop_read_exact(c->fd, buf, len, /* do_poll= */ true);
        if (r < 0)
                return r;

        *ret = IOVEC_MAKE(TAKE_PTR(buf), len);
        return 1;
}

static int ssh_agent_connection(void *userdata) {
        SshAgentConnection *c = ASSERT_PTR(userdata);
        int r;

        for (;;) {
                _cleanup_(iovec_done) struct iovec msg = {};

                r = read_message(c, &msg);
                if (r < 0)
                        return log_debug_errno(r, "ssh-agent: Failed to read message: %m");
                if (r == 0)
                        return 0;

                r = connection_dispatch_message(c, &msg);
                if (r < 0)
                        return log_debug_errno(r, "ssh-agent: Failed to process message: %m");
        }
}

static int ssh_agent_listen(void *userdata) {
        SshAgent *a = ASSERT_PTR(userdata);
        _cleanup_(sd_future_cancel_wait_unrefp) sd_future *connections = NULL;
        int r;

        r = sd_future_group_new(a->manager->event, &connections);
        if (r < 0)
                return log_error_errno(r, "ssh-agent: Failed to allocate connection group: %m");

        /* Without SD_FUTURE_GROUP_IGNORE_ERRORS, a failed connection cancels the listener fiber and all other
         * connections. */
        r = sd_future_group_set_policy(connections, SD_FUTURE_GROUP_IGNORE_ERRORS);
        if (r < 0)
                return log_error_errno(r, "ssh-agent: Failed to set connection group policy: %m");

        for (;;) {
                _cleanup_close_ int fd = sd_fiber_accept(a->listen_fd, /* addr= */ NULL, /* addrlen= */ NULL, SOCK_NONBLOCK|SOCK_CLOEXEC);
                if (ERRNO_IS_NEG_ACCEPT_AGAIN(fd))
                        continue;
                if (fd == -ECANCELED)
                        return fd;
                /* accept() keeps the connection in the queue when it fails with an error such as EMFILE. The
                 * next accept() then fails right away without suspending the fiber, and a retry loop would
                 * block the event loop. Stop accepting connections instead, like sd-varlink does. */
                if (fd < 0)
                        return log_warning_errno(fd, "ssh-agent: Failed to accept connection for machine %s, no longer accepting connections: %m",
                                                 a->machine_name);

                _cleanup_(ssh_agent_connection_freep) SshAgentConnection *c = new(SshAgentConnection, 1);
                if (!c) {
                        log_oom_warning();
                        continue;
                }

                *c = (SshAgentConnection) {
                        .agent = a,
                        .fd = TAKE_FD(fd),
                };

                /* If sd_fiber_set_destroy_callback() fails, the cleanup of f cancels the fiber before it
                 * starts. A fiber that is cancelled before it starts never runs. The cleanup of c can then
                 * free the connection. */
                _cleanup_(sd_future_cancel_unrefp) sd_future *f = NULL;
                r = sd_future_group_spawn(connections, "ssh-agent-connection", ssh_agent_connection, c, &f);
                if (r < 0) {
                        log_warning_errno(r, "ssh-agent: Failed to start connection fiber, ignoring: %m");
                        continue;
                }

                r = sd_fiber_set_destroy_callback(f, ssh_agent_connection_destroy);
                if (r < 0) {
                        log_warning_errno(r, "ssh-agent: Failed to set destroy callback of connection fiber, ignoring: %m");
                        continue;
                }

                TAKE_PTR(c);
                f = sd_future_unref(f);
        }
}

static int machine_ssh_agent_paths(const Machine *machine, char **ret_socket_path, char **ret_symlink_path) {
        _cleanup_free_ char *socket_path = NULL, *symlink_path = NULL;
        int r;

        assert(machine);
        assert(machine->manager);
        assert(ret_socket_path);
        assert(ret_symlink_path);

        r = runtime_directory_generic(
                        machine->manager->runtime_scope,
                        strjoina(SSH_AGENT_DIRECTORY "/machine/", machine->name),
                        &socket_path);
        if (r < 0)
                return r;

        r = runtime_directory_generic(
                        machine->manager->runtime_scope,
                        strjoina(SSH_AGENT_DIRECTORY "/machine%", machine->name),
                        &symlink_path);
        if (r < 0)
                return r;

        *ret_socket_path = TAKE_PTR(socket_path);
        *ret_symlink_path = TAKE_PTR(symlink_path);
        return 0;
}

static int ssh_agent_listen_socket(const char *path, int *ret) {
        union sockaddr_union sa;
        int r;

        assert(path);
        assert(ret);

        r = sockaddr_un_set_path(&sa.un, path);
        if (r < 0)
                return r;
        socklen_t sa_len = r;

        _cleanup_close_ int fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0);
        if (fd < 0)
                return -errno;

        r = mkdir_parents(path, 0755);
        if (r < 0)
                return r;

        /* A previous instance of machined can have left a socket behind at the path. */
        (void) sockaddr_un_unlink(&sa.un);

        WITH_UMASK(0177)
                if (bind(fd, &sa.sa, sa_len) < 0)
                        return -errno;

        if (listen(fd, SOMAXCONN_DELUXE) < 0)
                return -errno;

        *ret = TAKE_FD(fd);
        return 0;
}

int machine_start_ssh_agent(Machine *machine) {
        _cleanup_free_ char *socket_path = NULL, *symlink_path = NULL;
        _cleanup_(sd_future_unrefp) sd_future *f = NULL;
        int r;

        assert(machine);
        assert(machine->manager);

        /* The ssh_config drop-in only sets IdentityAgent= to sockets in the runtime directory of the user. */
        if (machine->manager->runtime_scope != RUNTIME_SCOPE_USER)
                return 0;

        if (!machine->ssh_private_key_path || machine->ssh_agent)
                return 0;

        r = machine_ssh_agent_paths(machine, &socket_path, &symlink_path);
        if (r < 0)
                return log_warning_errno(r, "Failed to determine SSH agent socket path of machine %s: %m", machine->name);

        _cleanup_(ssh_agent_freep) SshAgent *a = new(SshAgent, 1);
        if (!a)
                return log_oom_warning();

        *a = (SshAgent) {
                .manager = machine->manager,
                .machine_name = strdup(machine->name),
                .listen_fd = -EBADF,
        };
        if (!a->machine_name)
                return log_oom_warning();

        r = ssh_agent_listen_socket(socket_path, &a->listen_fd);
        if (r < 0)
                return log_warning_errno(r, "Failed to listen on SSH agent socket %s of machine %s: %m", socket_path, machine->name);

        /* ssh appends the host name exactly as it was given on the command line, so "machine%<name>" needs a
         * path of its own. */
        r = symlink_atomic(strjoina("machine/", machine->name), symlink_path);
        if (r < 0) {
                (void) unlink(socket_path);
                return log_warning_errno(r, "Failed to create symlink %s to SSH agent socket of machine %s: %m", symlink_path, machine->name);
        }

        /* If sd_fiber_set_destroy_callback() fails, the cleanup of f drops the fiber before it starts, and
         * the cleanup of a frees the agent. */
        r = sd_fiber_new(machine->manager->event, "ssh-agent-listen", ssh_agent_listen, a, &f);
        if (r >= 0)
                r = sd_fiber_set_destroy_callback(f, ssh_agent_destroy);
        if (r < 0) {
                (void) unlink(symlink_path);
                (void) unlink(socket_path);
                return log_warning_errno(r, "Failed to start SSH agent of machine %s: %m", machine->name);
        }

        TAKE_PTR(a);
        machine->ssh_agent = TAKE_PTR(f);

        log_debug("Listening for SSH agent requests for machine %s on %s.", machine->name, socket_path);
        return 0;
}

void machine_stop_ssh_agent(Machine *machine) {
        _cleanup_free_ char *socket_path = NULL, *symlink_path = NULL;
        int r;

        assert(machine);

        if (!machine->ssh_agent)
                return;

        /* Remove the socket right away instead of in the destroy callback of the fiber, which runs later. A
         * new machine with the same name can bind the path before that. */
        r = machine_ssh_agent_paths(machine, &socket_path, &symlink_path);
        if (r < 0)
                log_debug_errno(r, "Failed to determine SSH agent socket path of machine %s, not removing it: %m", machine->name);
        else {
                (void) unlink(symlink_path);
                (void) unlink(socket_path);
        }

        r = sd_future_cancel(machine->ssh_agent);
        if (r < 0)
                log_debug_errno(r, "Failed to cancel SSH agent of machine %s, ignoring: %m", machine->name);

        /* sd_future_cancel() only queues the cancellation of a fiber that has started. The fiber stays
         * pending until the event loop runs it again, and dropping the last reference to a pending fiber
         * triggers an assertion. A floating fiber frees itself once it has finished. */
        if (sd_future_state(machine->ssh_agent) == SD_FUTURE_PENDING)
                assert_se(sd_fiber_set_floating(machine->ssh_agent, true) >= 0);

        machine->ssh_agent = sd_future_unref(machine->ssh_agent);
}
