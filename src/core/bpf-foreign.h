/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include "core-forward.h"

/*
 * Attach cgroup-bpf programs foreign to systemd, i.e. loaded to the kernel by an entity
 * external to systemd.
 */
int bpf_foreign_install(Unit *u);
