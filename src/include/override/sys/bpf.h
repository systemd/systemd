/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/bpf.h>          /* IWYU pragma: export */
#include <stddef.h>

/* Supported since kernel v3.18 (749730ce42a2121e1c88350d69478bff3994b10a). */
#if !HAVE_BPF
int missing_bpf(int cmd, union bpf_attr *attr, size_t size);
#  define bpf missing_bpf
#endif
