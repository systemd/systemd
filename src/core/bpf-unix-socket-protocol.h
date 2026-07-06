/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "core-forward.h"

int unix_socket_protocol_bpf_supported(void);

struct unix_socket_protocol_bpf* unix_socket_protocol_bpf_destroy(struct unix_socket_protocol_bpf *u);

int unix_socket_protocol_bpf_new(struct unix_socket_protocol_bpf **ret);
