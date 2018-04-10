/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2016 Lennart Poettering
***/

#include "resolved-manager.h"
#include "resolved-dns-question.h"
#include "resolved-dns-answer.h"

void manager_etc_hosts_flush(Manager *m);
int manager_etc_hosts_read(Manager *m);
int manager_etc_hosts_lookup(Manager *m, DnsQuestion* q, DnsAnswer **answer);
