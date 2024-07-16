/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* The SPDX header above is actually correct in claiming this was
 * LGPL-2.1-or-later, because it is. Since the kernel doesn't consider that
 * compatible with GPL we will claim this to be GPL however, which should be
 * fine given that LGPL-2.1-or-later downgrades to GPL if needed.
 */

#include "bpf-dlopen.h"

/* libbpf is used via dlopen(), so rename symbols */
#define bpf_object__attach_skeleton sym_bpf_object__attach_skeleton
#define bpf_object__detach_skeleton sym_bpf_object__detach_skeleton
#define bpf_object__destroy_skeleton sym_bpf_object__destroy_skeleton
#define bpf_object__load_skeleton sym_bpf_object__load_skeleton
#define bpf_object__open_skeleton sym_bpf_object__open_skeleton
#define bpf_program__fd sym_bpf_program__fd
#define bpf_prog_attach sym_bpf_prog_attach
#define bpf_prog_detach sym_bpf_prog_detach
#define bpf_map__fd sym_bpf_map__fd
#define ring_buffer__new sym_ring_buffer__new
#define ring_buffer__poll sym_ring_buffer__poll
#define ring_buffer__epoll_fd sym_ring_buffer__epoll_fd
#define ring_buffer__free sym_ring_buffer__free

#include "bpf/sysctl_monitor/sysctl-monitor.skel.h"
