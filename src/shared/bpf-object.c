/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <unistd.h>

#include "architecture.h"
#include "bpf-object.h"
#include "bpf-program-v2.h"
#include "fd-util.h"
#include "set.h"

static const int supported_archs[] = {
        ARCHITECTURE_X86_64
};

int bpf_object_cpu_arch_supported(int arch) {
        for (size_t i = 0; i < ELEMENTSOF(supported_archs); i++)
                if (arch == supported_archs[i])
                        return 1;

        return 0;
}

int bpf_object_new(
                const unsigned char *mem_buf,
                size_t size,
                const char *object_name,
                struct bpf_object **object) {
        _cleanup_(bpf_object_freep) struct bpf_object *p = NULL;
        /* Standard error code. */
        long err;

        assert(mem_buf);
        assert(size > 0);
        assert(object);

        DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts,
                .object_name = object_name,
        );

        p = bpf_object__open_mem(mem_buf, size, &opts);
        /* Should either point to a valid BPF object or store standard error code. */
        if (!p)
                return -EINVAL;

        err = libbpf_get_error(p);
        if (err)
                return -err;

        *object = TAKE_PTR(p);
        return 0;
}

struct bpf_object *bpf_object_free(struct bpf_object *object) {
        if (object)
                bpf_object__close(object);

        return NULL;
}

int bpf_object_load(struct bpf_object *object) {
        assert(object);

        /* libbpf logs kernel warnings with pr_warn. */
        if (bpf_object__load(object))
                return -EINVAL;

        return 0;
}

 DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(prog_hash_ops, void, trivial_hash_func, trivial_compare_func, BPFProgramV2, bpf_program_v2_free);

int bpf_object_get_programs(const struct bpf_object *object, Set **ret_progs) {
      _cleanup_(set_freep) Set *progs = NULL;
      enum bpf_attach_type atype;
      struct bpf_program *prog;
      const char *title;
      int r;

      assert(object);
      assert(ret_progs);
      assert(*ret_progs == NULL);

      bpf_object__for_each_program(prog, object) {
              _cleanup_(bpf_program_v2_freep) BPFProgramV2 *p = NULL;
              /* cleanup on fail path */
              _cleanup_close_ int dup_fd = -1;
              int prog_fd;

              title = bpf_program__section_name(prog);
              if (libbpf_attach_type_by_name(title, &atype))
                      return -EINVAL;

              prog_fd = bpf_program__fd(prog);
              if (prog_fd < 0)
                      return -EBADF;

              /* The lifetime of prog_fd is defined by the lifetime of bpf_object object.
               * Duplicate prog_fd to increase refcount in kernel to keep the program
               * loaded when bpf_object is destroyed.
               */
              dup_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
              if (dup_fd < 0)
                      return -errno;

              r = dup3(prog_fd, dup_fd, O_CLOEXEC);
              if (r < 0)
                      return r;

              r = bpf_program_v2_new(dup_fd, atype, &p);
              if (r < 0)
                      return r;

              TAKE_FD(dup_fd);
              r = set_ensure_consume(&progs, &prog_hash_ops, TAKE_PTR(p));
              if (r < 0)
                      return r;

      }
      *ret_progs = TAKE_PTR(progs);

      return 0;
}

int bpf_object_get_map_fd(const struct bpf_object *object, const char *map_name) {
        const struct bpf_map *map;
        int map_fd;

        assert(object);
        assert(map_name);

        map = bpf_object__find_map_by_name(object, map_name);
        if (!map)
                return -ENOENT;

        map_fd = bpf_map__fd(map);
        if (map_fd < 0)
                return -EBADF;

        return map_fd;
}

int bpf_object_resize_map(const struct bpf_object *object, const char *map_name, size_t max_entries) {
        struct bpf_map *map;

        assert(object);
        assert(map_name);

        map = bpf_object__find_map_by_name(object, map_name);
        if (!map)
                return -ENOENT;

        return bpf_map__resize(map, max_entries);
}
