/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "journald-server.h"
#include "socket-util.h"

void server_forward_socket(Server *s, const struct iovec *iovec, size_t n, int priority);
void server_open_vm_forward_socket(Server *s, const SocketAddress *addr);
void server_detect_unix_forward_socket(Server *s);
