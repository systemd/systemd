/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  This file is part of systemd.

  Copyright 2016 Daniel Mack

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "bpf-program.h"
#include "fd-util.h"
#include "log.h"
#include "missing.h"

int bpf_program_new(uint32_t prog_type, BPFProgram **ret) {
        _cleanup_(bpf_program_unrefp) BPFProgram *p = NULL;

        p = new0(BPFProgram, 1);
        if (!p)
                return log_oom();

        p->prog_type = prog_type;
        p->kernel_fd = -1;

        *ret = p;
        p = NULL;
        return 0;
}

BPFProgram *bpf_program_unref(BPFProgram *p) {
        if (!p)
                return NULL;

        safe_close(p->kernel_fd);
        free(p->instructions);

        return mfree(p);
}

int bpf_program_add_instructions(BPFProgram *p, const struct bpf_insn *instructions, size_t count) {

        assert(p);

        if (!GREEDY_REALLOC(p->instructions, p->allocated, p->n_instructions + count))
                return -ENOMEM;

        memcpy(p->instructions + p->n_instructions, instructions, sizeof(struct bpf_insn) * count);
        p->n_instructions += count;

        return 0;
}

int bpf_program_load_kernel(BPFProgram *p, char *log_buf, size_t log_size) {
        union bpf_attr attr;

        assert(p);

        if (p->kernel_fd >= 0)
                return -EBUSY;

        attr = (union bpf_attr) {
                .prog_type = p->prog_type,
                .insns = PTR_TO_UINT64(p->instructions),
                .insn_cnt = p->n_instructions,
                .license = PTR_TO_UINT64("GPL"),
                .log_buf = PTR_TO_UINT64(log_buf),
                .log_level = !!log_buf,
                .log_size = log_size,
        };

        p->kernel_fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
        if (p->kernel_fd < 0)
                return -errno;

        return 0;
}

int bpf_program_cgroup_attach(BPFProgram *p, int type, const char *path, uint32_t flags) {
        _cleanup_close_ int fd = -1;
        union bpf_attr attr;

        assert(p);
        assert(type >= 0);
        assert(path);

        fd = open(path, O_DIRECTORY|O_RDONLY|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        attr = (union bpf_attr) {
                .attach_type = type,
                .target_fd = fd,
                .attach_bpf_fd = p->kernel_fd,
                .attach_flags = flags,
        };

        if (bpf(BPF_PROG_ATTACH, &attr, sizeof(attr)) < 0)
                return -errno;

        return 0;
}

int bpf_program_cgroup_detach(int type, const char *path) {
        _cleanup_close_ int fd = -1;
        union bpf_attr attr;

        assert(path);

        fd = open(path, O_DIRECTORY|O_RDONLY|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        attr = (union bpf_attr) {
                .attach_type = type,
                .target_fd = fd,
        };

        if (bpf(BPF_PROG_DETACH, &attr, sizeof(attr)) < 0)
                return -errno;

        return 0;
}

int bpf_map_new(enum bpf_map_type type, size_t key_size, size_t value_size, size_t max_entries, uint32_t flags) {
        union bpf_attr attr = {
                .map_type = type,
                .key_size = key_size,
                .value_size = value_size,
                .max_entries = max_entries,
                .map_flags = flags,
        };
        int fd;

        fd = bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
        if (fd < 0)
                return -errno;

        return fd;
}

int bpf_map_update_element(int fd, const void *key, void *value) {

        union bpf_attr attr = {
                .map_fd = fd,
                .key = PTR_TO_UINT64(key),
                .value = PTR_TO_UINT64(value),
        };

        if (bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr)) < 0)
                return -errno;

        return 0;
}

int bpf_map_lookup_element(int fd, const void *key, void *value) {

        union bpf_attr attr = {
                .map_fd = fd,
                .key = PTR_TO_UINT64(key),
                .value = PTR_TO_UINT64(value),
        };

        if (bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr)) < 0)
                return -errno;

        return 0;
}
