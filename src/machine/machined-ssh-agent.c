/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/socket.h>

#include "sd-daemon.h"
#include "sd-future.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "io-util.h"
#include "iovec-util.h"
#include "log.h"
#include "machine.h"
#include "machined.h"
#include "machined-ssh-agent.h"
#include "ssh-util.h"
#include "string-util.h"
#include "strv.h"
#include "unaligned.h"

/* SSH agent protocol, see PROTOCOL.agent. */
#define SSH_AGENT_FAILURE              5
#define SSH_AGENTC_REQUEST_IDENTITIES 11
#define SSH_AGENT_IDENTITIES_ANSWER   12
#define SSH_AGENTC_SIGN_REQUEST       13
#define SSH_AGENT_SIGN_RESPONSE       14

#define MAX_AGENT_MESSAGE_SIZE (256U * 1024U)

typedef struct SshAgentConnection {
        Manager *manager;
        int fd;
} SshAgentConnection;

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

        for (struct iovec i = reply; iovec_is_set(&i);) {
                /* send() raises SIGPIPE when the peer has already closed the connection. MSG_NOSIGNAL
                 * makes send() fail with EPIPE instead. */
                ssize_t n = sd_fiber_send(c->fd, i.iov_base, i.iov_len, MSG_NOSIGNAL);
                if (ERRNO_IS_NEG_TRANSIENT(n))
                        continue;
                if (n < 0)
                        return (int) n;

                iovec_inc(&i, n);
        }

        return 0;
}

static int send_failure(SshAgentConnection *c) {
        assert(c);

        return send_reply(c, &IOVEC_MAKE_BYTE(SSH_AGENT_FAILURE));
}

static int machine_load_ssh_key(Machine *machine, OpenSSHKey **ret) {
        assert(machine);
        assert(machine->ssh_private_key_path);
        assert(ret);

        _cleanup_free_ char *pub_path = strjoin(machine->ssh_private_key_path, ".pub");
        if (!pub_path)
                return -ENOMEM;

        return openssh_key_load(machine->ssh_private_key_path, pub_path, ret);
}

/* Build the per-machine entry: string pubkey_blob || string "machine/<name>" */
static int append_identity(struct iovec *body, const Machine *machine, const struct iovec *blob) {
        int r;

        assert(body);
        assert(machine);
        assert(blob);

        _cleanup_free_ char *comment = strjoin("machine/", machine->name);
        if (!comment)
                return -ENOMEM;

        r = ssh_wire_append_string(body, blob);
        if (r < 0)
                return r;

        return ssh_wire_append_string(body, &IOVEC_MAKE_STRING(comment));
}

/* Handle SSH_AGENTC_REQUEST_IDENTITIES. See PROTOCOL.agent §4.4.
 *
 * Request payload: empty — just the leading type byte (already consumed by the dispatcher).
 *
 * Reply with SSH_AGENT_IDENTITIES_ANSWER:
 *
 *   byte    SSH_AGENT_IDENTITIES_ANSWER  (12)
 *   uint32  N                            — number of identities that follow
 *   [ for each i in 0..N-1: ]
 *       string  key_blob_i               — SSH wire-format public-key blob
 *       string  comment_i                — printable label, here "machine/<name>"
 *
 * The count is backfilled after the loop, since we don't know in advance how many machines
 * have a usable key pair. Machines without a registered ssh_private_key_path are skipped;
 * machines whose key pair fails to load are skipped with a debug log (but still skipped, so a
 * single bad key never wedges the whole listing). */
static int handle_request_identities(SshAgentConnection *c) {
        _cleanup_(iovec_done) struct iovec body = {};
        size_t count_offset;
        uint32_t count = 0;
        int r;

        assert(c);

        if (!iovec_append(&body, &IOVEC_MAKE_BYTE(SSH_AGENT_IDENTITIES_ANSWER)))
                return -ENOMEM;

        /* Reserve space for the count; we'll backfill it once we know N. */
        count_offset = body.iov_len;
        r = ssh_wire_append_u32(&body, 0);
        if (r < 0)
                return r;

        Machine *machine;
        HASHMAP_FOREACH(machine, c->manager->machines) {
                _cleanup_(openssh_key_freep) OpenSSHKey *k = NULL;

                if (!machine->ssh_private_key_path)
                        continue;

                /* Load the private key too, so that the agent doesn't advertise a key that it can't sign
                 * with. Skip a machine whose key fails to load, so that the client still gets the keys
                 * of the other machines. */
                r = machine_load_ssh_key(machine, &k);
                if (r < 0) {
                        log_debug_errno(r, "Skipping machine %s: failed to load SSH private key: %m", machine->name);
                        continue;
                }

                r = append_identity(&body, machine, &k->pubkey_blob);
                if (r < 0)
                        return r;

                count++;
        }

        unaligned_write_be32((uint8_t*) body.iov_base + count_offset, count);
        return send_reply(c, &body);
}

/* Returns 0 if no machine has a loadable key pair with the public key `blob`. */
static int find_ssh_key_by_pubkey(Manager *m, const struct iovec *blob, Machine **ret_machine, OpenSSHKey **ret_key) {
        Machine *machine;
        int r;

        assert(m);
        assert(blob);
        assert(ret_machine);
        assert(ret_key);

        HASHMAP_FOREACH(machine, m->machines) {
                _cleanup_free_ char *pub_path = NULL, *comment = NULL;
                _cleanup_(iovec_done) struct iovec pubkey_blob = {};
                _cleanup_(openssh_key_freep) OpenSSHKey *k = NULL;
                OpenSSHKeyType type;

                if (!machine->ssh_private_key_path)
                        continue;

                pub_path = strjoin(machine->ssh_private_key_path, ".pub");
                if (!pub_path)
                        return -ENOMEM;

                if (openssh_pubkey_load(pub_path, &type, &pubkey_blob, &comment) < 0)
                        continue;

                if (!iovec_equal(&pubkey_blob, blob))
                        continue;

                r = machine_load_ssh_key(machine, &k);
                if (r < 0) {
                        log_debug_errno(r, "Failed to load key pair for machine %s: %m", machine->name);
                        return 0;
                }

                /* machine_load_ssh_key() reads the .pub file a second time. If the file changed between
                 * the two reads, the loaded key is not the requested key. */
                if (!iovec_equal(&k->pubkey_blob, blob))
                        return 0;

                *ret_machine = machine;
                *ret_key = TAKE_PTR(k);
                return 1;
        }

        return 0;
}

/* Handle SSH_AGENTC_SIGN_REQUEST. See PROTOCOL.agent §4.5.1.
 *
 * Request payload (the leading byte has already been consumed):
 *
 *   string  key_blob       — SSH wire-format public-key blob; identifies which key to use
 *   string  data           — the bytes to sign (typically session_id || userauth_request)
 *   uint32  flags          — bitmap, see PROTOCOL.agent §4.5.1.
 *                             bit 1 (0x02): SSH_AGENT_RSA_SHA2_256
 *                             bit 2 (0x04): SSH_AGENT_RSA_SHA2_512
 *                             others ignored / RSA-only
 *
 * On success, reply with SSH_AGENT_SIGN_RESPONSE:
 *
 *   byte    SSH_AGENT_SIGN_RESPONSE  (14)
 *   string  signature_blob           — wrapping `string type_name || string sig`
 *
 * On any failure (malformed request, unknown key, sign failure) we reply with the single
 * byte SSH_AGENT_FAILURE — never tear down the connection, since the client may follow
 * up with another request. */
static int handle_sign_request(SshAgentConnection *c, struct iovec *payload) {
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

        Machine *machine = NULL;
        _cleanup_(openssh_key_freep) OpenSSHKey *k = NULL;
        r = find_ssh_key_by_pubkey(c->manager, &blob, &machine, &k);
        if (r < 0)
                return r;
        if (r == 0) {
                log_debug("ssh-agent: SIGN_REQUEST for unknown pubkey");
                return send_failure(c);
        }

        _cleanup_(iovec_done) struct iovec sig = {};
        r = openssh_key_sign(k, flags, &data, &sig);
        if (r < 0) {
                log_debug_errno(r, "Failed to sign for machine %s: %m", machine->name);
                return send_failure(c);
        }

        _cleanup_(iovec_done) struct iovec body = {};
        if (!iovec_append(&body, &IOVEC_MAKE_BYTE(SSH_AGENT_SIGN_RESPONSE)))
                return -ENOMEM;

        r = ssh_wire_append_string(&body, &sig);
        if (r < 0)
                return r;

        return send_reply(c, &body);
}

static int connection_dispatch_message(SshAgentConnection *c, const struct iovec *msg) {
        assert(c);
        assert(msg);

        if (!iovec_is_set(msg))
                return send_failure(c);

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
        Manager *m = ASSERT_PTR(userdata);
        _cleanup_(sd_future_cancel_wait_unrefp) sd_future *connections = NULL;
        int r;

        r = sd_future_group_new(m->event, &connections);
        if (r < 0)
                return log_error_errno(r, "ssh-agent: Failed to allocate connection group: %m");

        /* Without SD_FUTURE_GROUP_IGNORE_ERRORS, a failed connection cancels the listener fiber and all other
         * connections. */
        r = sd_future_group_set_policy(connections, SD_FUTURE_GROUP_IGNORE_ERRORS);
        if (r < 0)
                return log_error_errno(r, "ssh-agent: Failed to set connection group policy: %m");

        for (;;) {
                _cleanup_close_ int fd = sd_fiber_accept(m->ssh_agent_listen_fd, NULL, NULL, SOCK_NONBLOCK|SOCK_CLOEXEC);
                if (ERRNO_IS_NEG_ACCEPT_AGAIN(fd))
                        continue;
                if (fd == -ECANCELED)
                        return fd;
                if (fd < 0)
                        return log_warning_errno(fd, "ssh-agent: Failed to accept connection: %m");

                _cleanup_(ssh_agent_connection_freep) SshAgentConnection *c = new(SshAgentConnection, 1);
                if (!c) {
                        log_oom_warning();
                        continue;
                }

                *c = (SshAgentConnection) {
                        .manager = m,
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

int manager_ssh_agent_init(Manager *m) {
        _cleanup_strv_free_ char **names = NULL;
        int n, r, listen_fd = -EBADF;

        assert(m);

        n = sd_listen_fds_with_names(/* unset_environment= */ false, &names);
        if (n < 0)
                return log_error_errno(n, "ssh-agent: failed to acquire passed fd list: %m");

        for (int i = 0; i < n; i++)
                if (streq(names[i], "ssh-agent")) {
                        listen_fd = SD_LISTEN_FDS_START + i;
                        break;
                }

        if (listen_fd < 0) {
                log_debug("ssh-agent: no socket passed via socket activation, agent disabled");
                return 0;
        }

        r = fd_nonblock(listen_fd, true);
        if (r < 0)
                return log_error_errno(r, "ssh-agent: failed to make listen fd non-blocking: %m");

        m->ssh_agent_listen_fd = listen_fd;

        r = sd_fiber_new(m->event, "ssh-agent-listen", ssh_agent_listen, m, &m->ssh_agent_listener);
        if (r < 0)
                return log_error_errno(r, "ssh-agent: failed to start listener fiber: %m");

        log_debug("ssh-agent: listening on fd %d", listen_fd);
        return 0;
}

void manager_ssh_agent_done(Manager *m) {
        assert(m);

        m->ssh_agent_listener = sd_future_cancel_unref(m->ssh_agent_listener);
}
