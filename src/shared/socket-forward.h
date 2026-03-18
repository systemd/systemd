/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

/* Bidirectional socket forwarder using splice().
 *
 * Forwards data between two bidirectional sockets ("server" and "client") via kernel pipe buffers,
 * avoiding userspace copies.
 *
 * When forwarding completes (both directions reach EOF or error), the completion callback is invoked.
 *
 * The SocketForward takes ownership of both fds - they are closed when the SocketForward is freed
 * (or earlier, during normal forwarding when EOF/disconnect is detected). */

typedef struct SocketForward SocketForward;

typedef int (*socket_forward_done_t)(SocketForward *sf, int error, void *userdata);

int socket_forward_new(
                sd_event *event,
                int server_fd,
                int client_fd,
                socket_forward_done_t on_done,
                void *userdata,
                SocketForward **ret);

SocketForward* socket_forward_free(SocketForward *sf);
DEFINE_TRIVIAL_CLEANUP_FUNC(SocketForward*, socket_forward_free);
