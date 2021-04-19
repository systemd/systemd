/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "fdset.h"
#include "unit.h"

#if HAVE_LIBBPF
struct bpf_link;
struct SocketBind {
        FDSet *initial_link_fds;
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

/* Add BPF link fd created before daemon-reload or daemon-reexec.
 * FDs will be closed after at the end of install. */
int socket_bind_add_initial_link_fd(Unit *u, int fd);

int socket_bind_install(Unit *u);

int serialize_socket_bind(Unit *u, FILE *f, FDSet *fds);
