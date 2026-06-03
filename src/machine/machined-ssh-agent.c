/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/socket.h>
#include <unistd.h>

#include "sd-daemon.h"
#include "sd-event.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "log.h"
#include "machine.h"
#include "machined.h"
#include "machined-ssh-agent.h"
#include "ssh-util.h"
#include "string-util.h"
#include "strv.h"
#include "unaligned.h"

/* SSH agent protocol, see PROTOCOL.agent. */
#define SSH_AGENT_FAILURE         5
#define SSH_AGENTC_REQUEST_IDENTITIES 11
#define SSH_AGENT_IDENTITIES_ANSWER   12
#define SSH_AGENTC_SIGN_REQUEST       13
#define SSH_AGENT_SIGN_RESPONSE       14

#define MAX_AGENT_MESSAGE_SIZE (256U * 1024U)

struct SshAgentConnection {
        Manager *manager;
        int fd;
        sd_event_source *io_source;

        /* Read accumulator: appended to until a full message (uint32 length + length bytes)
         * is available, then consumed. */
        SshWireBuf rbuf;

        /* Queued outgoing reply. wbuf_pos tracks how many bytes have been written to the
         * socket so far across short writes; (wbuf.size - wbuf_pos) is what's left to send. */
        SshWireBuf wbuf;
        size_t wbuf_pos;

        /* Set once read() returned 0: we stop reading and close as soon as any queued
         * reply has been drained. */
        bool peer_eof;

        LIST_FIELDS(SshAgentConnection, link);
};

static SshAgentConnection* ssh_agent_connection_free(SshAgentConnection *c) {
        if (!c)
                return NULL;

        if (c->manager)
                LIST_REMOVE(link, c->manager->ssh_agent_connections, c);

        c->io_source = sd_event_source_disable_unref(c->io_source);
        safe_close(c->fd);
        ssh_wire_buf_done(&c->rbuf);
        ssh_wire_buf_done(&c->wbuf);
        return mfree(c);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(SshAgentConnection*, ssh_agent_connection_free);

/* Queue an outgoing message: prepend a uint32 length to the body. Resets wbuf_pos.
 * Caller must ensure any previously queued reply has been fully drained — the
 * dispatcher already enforces this by deferring further reads while wbuf is non-empty. */
static int queue_reply(SshAgentConnection *c, const SshWireBuf *body) {
        int r;

        assert(c);
        assert(body);
        assert(!c->wbuf.data || c->wbuf_pos >= c->wbuf.size);

        ssh_wire_buf_done(&c->wbuf);
        c->wbuf_pos = 0;

        if (body->size > UINT32_MAX)
                return -EMSGSIZE;

        r = ssh_wire_buf_append_u32(&c->wbuf, body->size);
        if (r < 0)
                return r;

        return ssh_wire_buf_append_bytes(&c->wbuf, body->data, body->size);
}

static int queue_failure(SshAgentConnection *c) {
        assert(c);

        _cleanup_(ssh_wire_buf_done) SshWireBuf body = {};
        int r = ssh_wire_buf_append_byte(&body, SSH_AGENT_FAILURE);
        if (r < 0)
                return r;

        return queue_reply(c, &body);
}

/* Build the per-machine entry: string pubkey_blob || string "machine/<name>" */
static int append_identity(SshWireBuf *body, const Machine *m, const void *blob, size_t blob_size) {
        assert(body);
        assert(m);
        assert(blob || blob_size == 0);

        _cleanup_free_ char *comment = strjoin("machine/", m->name);
        if (!comment)
                return -ENOMEM;

        int r = ssh_wire_buf_append_string(body, blob, blob_size);
        if (r < 0)
                return r;

        return ssh_wire_buf_append_string(body, comment, SIZE_MAX);
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
        _cleanup_(ssh_wire_buf_done) SshWireBuf body = {};
        size_t count_offset;
        uint32_t count = 0;
        int r;

        assert(c);

        r = ssh_wire_buf_append_byte(&body, SSH_AGENT_IDENTITIES_ANSWER);
        if (r < 0)
                return r;

        /* Reserve space for the count; we'll backfill it once we know N. */
        count_offset = body.size;
        r = ssh_wire_buf_append_u32(&body, 0);
        if (r < 0)
                return r;

        Machine *m;
        HASHMAP_FOREACH(m, c->manager->machines) {
                _cleanup_free_ char *pub_path = NULL;
                _cleanup_(openssh_key_freep) OpenSSHKey *k = NULL;

                if (!m->ssh_private_key_path)
                        continue;

                pub_path = strjoin(m->ssh_private_key_path, ".pub");
                if (!pub_path)
                        return -ENOMEM;

                /* Load the full key pair (not just the .pub): keys we couldn't sign with anyway — in
                 * particular ones ssh-keygen wrote in the OpenSSH native rather than PKCS#8 format
                 * (openssh_key_load() returns -EOPNOTSUPP for those) — are silently not advertised. Other
                 * failures are genuine and propagate. */
                r = openssh_key_load(m->ssh_private_key_path, pub_path, &k);
                if (r == -EOPNOTSUPP) {
                        log_debug_errno(r, "Skipping machine %s: SSH private key is not in a supported format.", m->name);
                        continue;
                }
                if (r < 0)
                        return r;

                r = append_identity(&body, m, k->pubkey_blob, k->pubkey_blob_size);
                if (r < 0)
                        return r;

                count++;
        }

        unaligned_write_be32(body.data + count_offset, count);
        return queue_reply(c, &body);
}

/* Find a machine whose .pub blob matches `blob`. Returns 0 with *ret=NULL if no match. */
static int find_machine_by_pubkey(Manager *mgr, const void *blob, size_t blob_size, Machine **ret) {
        Machine *m;

        assert(mgr);
        assert(blob || blob_size == 0);
        assert(ret);

        HASHMAP_FOREACH(m, mgr->machines) {
                _cleanup_free_ char *pub_path = NULL;
                _cleanup_free_ void *kblob = NULL;
                _cleanup_free_ char *kcomment = NULL;
                size_t kblob_size = 0;
                OpenSSHKeyType ktype;

                if (!m->ssh_private_key_path)
                        continue;

                pub_path = strjoin(m->ssh_private_key_path, ".pub");
                if (!pub_path)
                        return -ENOMEM;

                if (openssh_pubkey_load(pub_path, &ktype, &kblob, &kblob_size, &kcomment) < 0)
                        continue;

                if (kblob_size == blob_size && memcmp(kblob, blob, blob_size) == 0) {
                        *ret = m;
                        return 1;
                }
        }

        *ret = NULL;
        return 0;
}

/* Handle SSH_AGENTC_SIGN_REQUEST. See PROTOCOL.agent §4.5.1.
 *
 * Request payload (the leading byte has already been consumed; `rc` points at the rest):
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
static int handle_sign_request(SshAgentConnection *c, SshWireCursor *rc) {
        const uint8_t *blob, *data;
        size_t blob_size, data_size;
        uint32_t flags;
        int r;

        assert(c);
        assert(rc);

        r = ssh_wire_cursor_read_string(rc, &blob, &blob_size);
        if (r < 0)
                return queue_failure(c);

        r = ssh_wire_cursor_read_string(rc, &data, &data_size);
        if (r < 0)
                return queue_failure(c);

        r = ssh_wire_cursor_read_u32(rc, &flags);
        if (r < 0)
                return queue_failure(c);

        Machine *m = NULL;
        r = find_machine_by_pubkey(c->manager, blob, blob_size, &m);
        if (r <= 0 || !m) {
                log_debug("ssh-agent: SIGN_REQUEST for unknown pubkey");
                return queue_failure(c);
        }

        _cleanup_free_ char *pub_path = strjoin(m->ssh_private_key_path, ".pub");
        if (!pub_path)
                return -ENOMEM;

        _cleanup_(openssh_key_freep) OpenSSHKey *k = NULL;
        r = openssh_key_load(m->ssh_private_key_path, pub_path, &k);
        if (r < 0) {
                log_debug_errno(r, "Failed to load key pair for machine %s: %m", m->name);
                return queue_failure(c);
        }

        _cleanup_free_ void *sig = NULL;
        size_t sig_size = 0;
        r = openssh_key_sign(k, flags, data, data_size, &sig, &sig_size);
        if (r < 0) {
                log_debug_errno(r, "Failed to sign for machine %s: %m", m->name);
                return queue_failure(c);
        }

        _cleanup_(ssh_wire_buf_done) SshWireBuf body = {};
        r = ssh_wire_buf_append_byte(&body, SSH_AGENT_SIGN_RESPONSE);
        if (r < 0)
                return r;

        r = ssh_wire_buf_append_string(&body, sig, sig_size);
        if (r < 0)
                return r;

        return queue_reply(c, &body);
}

static int connection_dispatch_message(SshAgentConnection *c, const uint8_t *msg, size_t msg_size) {
        assert(c);
        assert(msg || msg_size == 0);

        SshWireCursor rc = { .data = msg, .size = msg_size, .pos = 0 };

        if (msg_size == 0)
                return queue_failure(c);

        uint8_t type = msg[0];
        rc.pos = 1;

        switch (type) {
        case SSH_AGENTC_REQUEST_IDENTITIES:
                return handle_request_identities(c);
        case SSH_AGENTC_SIGN_REQUEST:
                return handle_sign_request(c, &rc);
        default:
                log_debug("ssh-agent: unsupported message type %u, replying FAILURE", type);
                return queue_failure(c);
        }
}

static int connection_arm_io(SshAgentConnection *c);

/* Drains any queued reply. Returns:
 *   < 0  → fatal, caller should close the connection
 *   = 0  → drained fully (or nothing was queued); proceed to read
 *   > 0  → would-block / partial; caller should arm EPOLLOUT and return */
static int connection_write(SshAgentConnection *c) {
        ssize_t n;

        assert(c);

        if (!c->wbuf.data || c->wbuf_pos >= c->wbuf.size)
                return 0;

        for (;;) {
                n = write(c->fd, c->wbuf.data + c->wbuf_pos, c->wbuf.size - c->wbuf_pos);
                if (n >= 0)
                        break;
                if (errno == EINTR)
                        continue;
                if (errno == EAGAIN)
                        return 1;
                return log_debug_errno(errno, "ssh-agent write failed: %m");
        }

        c->wbuf_pos += n;
        if (c->wbuf_pos < c->wbuf.size)
                return 1;

        /* Fully written. */
        ssh_wire_buf_done(&c->wbuf);
        c->wbuf_pos = 0;
        return 0;
}

/* Pulls available bytes off the socket into the read accumulator. Returns:
 *   < 0  → fatal, caller should close the connection
 *   = 0  → success; peer-closed is signalled by c->peer_eof rather than an error */
static int connection_read(SshAgentConnection *c) {
        uint8_t tmp[4096];
        ssize_t n;

        assert(c);

        for (;;) {
                n = read(c->fd, tmp, sizeof(tmp));
                if (n >= 0)
                        break;
                if (errno == EINTR)
                        continue;
                if (errno == EAGAIN)
                        return 0;
                return log_debug_errno(errno, "ssh-agent read failed: %m");
        }
        if (n == 0) {
                /* Peer closed: stop reading, but let the caller still dispatch any
                 * complete buffered request and drain any reply before closing. */
                c->peer_eof = true;
                return 0;
        }

        if (c->rbuf.size + (size_t) n > MAX_AGENT_MESSAGE_SIZE + 4)
                return log_debug_errno(SYNTHETIC_ERRNO(EMSGSIZE), "ssh-agent: oversized message");

        return ssh_wire_buf_append_bytes(&c->rbuf, tmp, n);
}

/* Walks the read accumulator, dispatching any fully-received messages. Returns:
 *   < 0  → fatal, caller should close the connection
 *   = 0  → success (no more complete messages, or a reply is pending) */
static int connection_dispatch(SshAgentConnection *c) {
        assert(c);

        while (c->rbuf.size >= 4) {
                uint32_t mlen = unaligned_read_be32(c->rbuf.data);
                if (mlen == 0 || mlen > MAX_AGENT_MESSAGE_SIZE)
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "ssh-agent: invalid message length %u", mlen);
                if (c->rbuf.size < 4 + mlen)
                        break;

                /* If we already have a queued reply not yet sent, defer further processing. */
                if (c->wbuf.data && c->wbuf_pos < c->wbuf.size)
                        break;

                int r = connection_dispatch_message(c, c->rbuf.data + 4, mlen);
                if (r < 0)
                        return log_debug_errno(r, "ssh-agent: failed to process message: %m");

                /* Consume from the read buffer. */
                size_t consumed = 4 + mlen;
                memmove(c->rbuf.data, c->rbuf.data + consumed, c->rbuf.size - consumed);
                c->rbuf.size -= consumed;
        }

        return 0;
}

static int on_connection_io(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        /* On any error path we want to drop the connection; disarm the cleanup on the
         * success path with TAKE_PTR. */
        _cleanup_(ssh_agent_connection_freep) SshAgentConnection *c = ASSERT_PTR(userdata);
        int r;

        r = connection_write(c);
        if (r < 0)
                return 0;

        /* Read on EPOLLIN; also on EPOLLHUP, since the peer may have sent a complete
         * request followed by shutdown(SHUT_WR) and still expect a reply. */
        if (!c->peer_eof && (revents & (EPOLLIN|EPOLLHUP|EPOLLERR))) {
                r = connection_read(c);
                if (r < 0)
                        return 0;
        }

        r = connection_dispatch(c);
        if (r < 0)
                return 0;

        /* Once the peer has closed its write side and we have nothing more to send,
         * tear the connection down. */
        if (c->peer_eof && (!c->wbuf.data || c->wbuf_pos >= c->wbuf.size))
                return 0;

        r = connection_arm_io(c);
        if (r < 0)
                return r;

        TAKE_PTR(c);
        return r;
}

static int connection_arm_io(SshAgentConnection *c) {
        assert(c);

        uint32_t events = 0;
        if (!c->peer_eof)
                events |= EPOLLIN;
        if (c->wbuf.data && c->wbuf_pos < c->wbuf.size)
                events |= EPOLLOUT;

        return sd_event_source_set_io_events(c->io_source, events);
}

static int on_listen_io(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        /* Accept at most one connection per event tick. sd_event will re-fire us if more
         * connections are pending; looping here is unsafe because the inherited listen FD
         * may be in blocking mode (socket-activated AF_UNIX listen FDs are not guaranteed
         * to have O_NONBLOCK set), in which case the second accept4 would block forever
         * and the systemd watchdog would kill us. */
        _cleanup_close_ int cfd = accept4(fd, NULL, NULL, SOCK_NONBLOCK|SOCK_CLOEXEC);
        if (cfd < 0) {
                if (IN_SET(errno, EAGAIN, EINTR))
                        return 0;

                return log_warning_errno(errno, "ssh-agent: accept4 failed: %m");
        }

        _cleanup_(ssh_agent_connection_freep) SshAgentConnection *c = new0(SshAgentConnection, 1);
        if (!c)
                return log_oom();

        c->manager = m;
        c->fd = TAKE_FD(cfd);

        r = sd_event_add_io(m->event, &c->io_source, c->fd, EPOLLIN, on_connection_io, c);
        if (r < 0)
                return log_warning_errno(r, "ssh-agent: failed to add connection io source: %m");
        (void) sd_event_source_set_description(c->io_source, "machined-ssh-agent-conn");

        LIST_PREPEND(link, m->ssh_agent_connections, c);
        TAKE_PTR(c);
        return 0;
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

        r = sd_event_add_io(m->event, &m->ssh_agent_listen_source, listen_fd, EPOLLIN, on_listen_io, m);
        if (r < 0)
                return log_error_errno(r, "ssh-agent: failed to add listen io source: %m");

        (void) sd_event_source_set_description(m->ssh_agent_listen_source, "machined-ssh-agent-listen");

        log_debug("ssh-agent: listening on fd %d", listen_fd);
        return 0;
}

void manager_ssh_agent_done(Manager *m) {
        assert(m);

        while (m->ssh_agent_connections)
                ssh_agent_connection_free(m->ssh_agent_connections);

        m->ssh_agent_listen_source = sd_event_source_disable_unref(m->ssh_agent_listen_source);
}
