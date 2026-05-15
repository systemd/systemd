/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/bpf.h>          /* IWYU pragma: export */
#include <stddef.h>

/* Supported since kernel v3.18 (749730ce42a2121e1c88350d69478bff3994b10a). */
int bpf_shim(int cmd, union bpf_attr *attr, size_t size);
#define bpf bpf_shim
