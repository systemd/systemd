/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering
***/

#include "journald-server.h"

int server_open_dev_kmsg(Server *s);
int server_flush_dev_kmsg(Server *s);

void server_forward_kmsg(Server *s, int priority, const char *identifier, const char *message, const struct ucred *ucred);

int server_open_kernel_seqnum(Server *s);
