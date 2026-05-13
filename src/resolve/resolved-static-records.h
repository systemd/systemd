/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "resolved-forward.h"

void manager_static_records_flush(Manager *m);
int manager_static_records_lookup(Manager *m, DnsQuestion* q, DnsAnswer **answer);
