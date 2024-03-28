/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* The SPDX header above is actually correct in claiming this was
 * LGPL-2.1-or-later, because it is. Since the kernel doesn't consider that
 * compatible with GPL we will claim this to be GPL however, which should be
 * fine given that LGPL-2.1-or-later downgrades to GPL if needed.
 */

#include "bpf-dlopen.h"

/* libbpf is used via dlopen(), so rename symbols */
#define bpf_object__attach_skeleton sym_bpf_object__attach_skeleton
#define bpf_object__destroy_skeleton sym_bpf_object__destroy_skeleton
#define bpf_object__load_skeleton sym_bpf_object__load_skeleton
#define bpf_object__open_skeleton sym_bpf_object__open_skeleton

#include "bpf/userns_restrict/userns-restrict.skel.h"
