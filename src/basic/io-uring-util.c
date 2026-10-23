/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "errno-util.h"
#include "fd-util.h"
#include "io-uring-util.h"

static int io_uring_setup(unsigned entries, struct io_uring_params *p) {
        return RET_NERRNO((int) syscall(__NR_io_uring_setup, entries, p));
}

static int io_uring_enter(int fd, unsigned to_submit, unsigned min_complete, unsigned flags) {
        return RET_NERRNO((int) syscall(__NR_io_uring_enter, fd, to_submit, min_complete, flags, NULL, 0));
}

int io_uring_init(IoUring *ring, unsigned entries, unsigned flags) {
        _cleanup_close_ int fd = -EBADF;

        assert(ring);
        assert(!io_uring_is_initialized(ring));
        /* io_uring_get_sqe() and IO_URING_FOREACH_CQE() assume 64-byte SQEs and 16-byte CQEs. With bigger
         * or mixed entry sizes, they would return pointers into the middle of an entry. */
        assert((flags & (IORING_SETUP_SQE128|IORING_SETUP_CQE32|IORING_SETUP_CQE_MIXED|IORING_SETUP_SQE_MIXED)) == 0);
        /* With SQPOLL, a kernel thread reads the SQ ring and has to be woken up with
         * IORING_ENTER_SQ_WAKEUP. io_uring_submit() never passes that flag. */
        assert((flags & IORING_SETUP_SQPOLL) == 0);

        struct io_uring_params p = {
                .flags = flags,
        };

        fd = io_uring_setup(entries, &p);
        if (fd < 0)
                return fd;

        /* Kernels before 5.4 need separate mappings for the SQ ring and the CQ ring. We don't support
         * them, because sd-event needs kernel 5.19 for its setup flags anyway. */
        if (!FLAGS_SET(p.features, IORING_FEAT_SINGLE_MMAP))
                return -EOPNOTSUPP;

        size_t ring_size = MAX(p.sq_off.array + p.sq_entries * sizeof(uint32_t),
                               p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe));
        void *r = mmap(NULL, ring_size, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_POPULATE, fd, IORING_OFF_SQ_RING);
        if (r == MAP_FAILED)
                return -errno;

        size_t sqes_size = p.sq_entries * sizeof(struct io_uring_sqe);
        void *sqes = mmap(NULL, sqes_size, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_POPULATE, fd, IORING_OFF_SQES);
        if (sqes == MAP_FAILED) {
                int k = -errno;
                (void) munmap(r, ring_size);
                return k;
        }

        *ring = (IoUring) {
                .ring_fd = TAKE_FD(fd),
                .ring = r,
                .ring_size = ring_size,
                .sq_head = (uint32_t*) ((uint8_t*) r + p.sq_off.head),
                .sq_tail = (uint32_t*) ((uint8_t*) r + p.sq_off.tail),
                .sq_flags = (uint32_t*) ((uint8_t*) r + p.sq_off.flags),
                .sq_mask = *(uint32_t*) ((uint8_t*) r + p.sq_off.ring_mask),
                .sq_entries = *(uint32_t*) ((uint8_t*) r + p.sq_off.ring_entries),
                .sqes = sqes,
                .sqes_size = sqes_size,
                .cq_head = (uint32_t*) ((uint8_t*) r + p.cq_off.head),
                .cq_tail = (uint32_t*) ((uint8_t*) r + p.cq_off.tail),
                .cq_mask = *(uint32_t*) ((uint8_t*) r + p.cq_off.ring_mask),
                .cqes = (struct io_uring_cqe*) ((uint8_t*) r + p.cq_off.cqes),
        };

        ring->sqe_tail = *ring->sq_tail;

        /* The SQ array maps each slot of the SQ ring to an SQE. We fill in the SQEs in ring order, so
         * slot i always points to SQE i. */
        uint32_t *array = (uint32_t*) ((uint8_t*) r + p.sq_off.array);
        for (uint32_t i = 0; i < ring->sq_entries; i++)
                array[i] = i;

        return 0;
}

void io_uring_done(IoUring *ring) {
        assert(ring);

        if (!io_uring_is_initialized(ring))
                return;

        (void) munmap(ring->sqes, ring->sqes_size);
        (void) munmap(ring->ring, ring->ring_size);
        safe_close(ring->ring_fd);

        *ring = IO_URING_NULL;
}

struct io_uring_sqe* io_uring_get_sqe(IoUring *ring) {
        assert(ring);
        assert(io_uring_is_initialized(ring));

        /* The kernel advances the SQ head after it read the SQEs. The acquire load makes sure that the
         * kernel finished reading an SQE before we reuse its slot. */
        uint32_t head = __atomic_load_n(ring->sq_head, __ATOMIC_ACQUIRE);
        if (ring->sqe_tail - head >= ring->sq_entries)
                return NULL;

        struct io_uring_sqe *sqe = &ring->sqes[ring->sqe_tail & ring->sq_mask];
        ring->sqe_tail++;

        *sqe = (struct io_uring_sqe) {};
        return sqe;
}

int io_uring_submit(IoUring *ring) {
        unsigned flags = 0;

        assert(ring);
        assert(io_uring_is_initialized(ring));

        /* The release store makes sure that the kernel sees the filled in SQEs once it sees the new
         * tail. */
        __atomic_store_n(ring->sq_tail, ring->sqe_tail, __ATOMIC_RELEASE);
        unsigned to_submit = ring->sqe_tail - __atomic_load_n(ring->sq_head, __ATOMIC_RELAXED);

        /* When the CQ ring is full, the kernel keeps further CQEs on an overflow list and sets
         * IORING_SQ_CQ_OVERFLOW. With IORING_SETUP_COOP_TASKRUN, it sets IORING_SQ_TASKRUN when task work
         * is waiting to post CQEs. In both cases, the CQEs only end up in the CQ ring when we enter the
         * kernel with IORING_ENTER_GETEVENTS. */
        if (__atomic_load_n(ring->sq_flags, __ATOMIC_RELAXED) & (IORING_SQ_CQ_OVERFLOW|IORING_SQ_TASKRUN))
                flags |= IORING_ENTER_GETEVENTS;

        if (to_submit == 0 && flags == 0)
                return 0;

        return io_uring_enter(ring->ring_fd, to_submit, /* min_complete= */ 0, flags);
}
