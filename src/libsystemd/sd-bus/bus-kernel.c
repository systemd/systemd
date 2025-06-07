/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/mman.h>

#include "bus-kernel.h"
#include "bus-internal.h"
#include "fd-util.h"
#include "memory-util.h"

void close_and_munmap(int fd, void *address, size_t size) {
        if (size > 0) {
                size = PAGE_ALIGN(size);
                assert(size < SIZE_MAX);
                assert_se(munmap(address, size) >= 0);
        }

        safe_close(fd);
}

void bus_flush_memfd(sd_bus *b) {
        assert(b);

        for (unsigned i = 0; i < b->n_memfd_cache; i++)
                close_and_munmap(b->memfd_cache[i].fd, b->memfd_cache[i].address, b->memfd_cache[i].mapped);
}
