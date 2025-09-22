/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/socket.h>

#include "journald-forward.h"

void manager_process_audit_message(Manager *m, const void *buffer, size_t buffer_size, const struct ucred *ucred, const union sockaddr_union *sa, socklen_t salen);

void process_audit_string(Manager *m, int type, const char *data, size_t size);

int manager_open_audit(Manager *m);
void manager_reset_kernel_audit(Manager *m, AuditSetMode old_set_audit);
