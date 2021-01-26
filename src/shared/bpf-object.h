/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "macro.h"

typedef struct Set Set;

int bpf_object_cpu_arch_supported(int arch) _const_;

int bpf_object_new(const unsigned char *mem_buf, size_t size, struct bpf_object **object);
struct bpf_object *bpf_object_free(struct bpf_object *object);

int bpf_object_load(struct bpf_object *object);
int bpf_object_get_programs(const struct bpf_object *object, Set **progs);
int bpf_object_get_map_fd(const struct bpf_object *object, const char *map_name);
int bpf_object_resize_map(const struct bpf_object *object, const char *map_name, size_t max_entries);

DEFINE_TRIVIAL_CLEANUP_FUNC(struct bpf_object *, bpf_object_free);
