/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "journald-server.h"
#include "socket-util.h"

void server_process_audit_message(Server *s, const void *buffer, size_t buffer_size, const struct ucred *ucred, const union sockaddr_union *sa, socklen_t salen);

void process_audit_string(Server *s, int type, const char *data, size_t size);

int server_open_audit(Server *s);
