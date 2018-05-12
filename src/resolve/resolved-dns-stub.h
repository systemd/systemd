/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2016 Lennart Poettering
***/

#include "resolved-manager.h"

void manager_dns_stub_stop(Manager *m);
int manager_dns_stub_start(Manager *m);
