/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "unit.h"

#if HAVE_LIBBPF
struct bpf_link;
struct SocketBind {
        struct bpf_link *ipv4_link;
        struct bpf_link *ipv6_link;
};
#else
struct SocketBind {
};
#endif
typedef struct SocketBind SocketBind;

SocketBind *socket_bind_free(SocketBind *socket_bind);

int socket_bind_supported(void);

int socket_bind_install(Unit *u);
