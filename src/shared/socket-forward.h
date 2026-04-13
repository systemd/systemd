/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

/* Bidirectional forwarder using splice().
 *
 * Forwards data between two sides ("server" and "client") via kernel pipe buffers,
 * avoiding userspace copies. Internally uses two independent half-duplex forwarders,
 * one per direction. All four fds must be distinct - use dup()/fcntl(fd, F_DUPFD_CLOEXEC, 3) for bidirectional sockets.
 *
 * When forwarding completes (both directions reach EOF or error), the completion callback is invoked.
 *
 * The SocketForward takes ownership of all fds - they are closed when the SocketForward is freed
 * (or earlier, during normal forwarding when EOF/disconnect is detected). */

typedef struct SocketForward SocketForward;

typedef int (*socket_forward_done_t)(SocketForward *sf, int error, void *userdata);

/* Create a forwarder between two bidirectional sockets. */
int socket_forward_new(
                sd_event *event,
                int server_fd,
                int client_fd,
                socket_forward_done_t on_done,
                void *userdata,
                SocketForward **ret);

/* Create a forwarder between two fd pairs (e.g. stdin/stdout on one side, socket on the other).
 * All four fds must be distinct - use dup()/fcntl(fd, F_DUPFD_CLOEXEC, 3) for bidirectional sockets. */
int socket_forward_new_pair(
                sd_event *event,
                int server_read_fd,
                int server_write_fd,
                int client_read_fd,
                int client_write_fd,
                socket_forward_done_t on_done,
                void *userdata,
                SocketForward **ret);

SocketForward* socket_forward_free(SocketForward *sf);
DEFINE_TRIVIAL_CLEANUP_FUNC(SocketForward*, socket_forward_free);
