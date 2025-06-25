/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "journald-forward.h"

int manager_open_varlink(Manager *m, const char *socket, int fd);

void sync_req_varlink_reply(SyncReq *req);
