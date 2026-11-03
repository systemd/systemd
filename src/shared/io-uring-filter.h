/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

int io_uring_bpf_filter_supported(void);

int io_uring_restrict_ops(Set *ops, bool allow_list);
int io_uring_restrict_address_families(Set *address_families, bool allow_list);
int io_uring_restrict_suid_sgid(void);
