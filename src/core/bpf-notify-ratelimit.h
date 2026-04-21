/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "core-forward.h"

int bpf_notify_ratelimit_install(Unit *u);
int bpf_notify_ratelimit_cleanup(Unit *u);
void bpf_notify_ratelimit_destroy(struct notify_ratelimit_bpf *obj);
int bpf_notify_ratelimit_serialize(Unit *u, FILE *f, FDSet *fds);
