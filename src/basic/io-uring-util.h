/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <endian.h>
#include <linux/io_uring.h>     /* IWYU pragma: export */
#include <sys/socket.h>

#include "forward.h"

typedef struct IoUring {
        int ring_fd;

        void *ring;
        size_t ring_size;

        uint32_t *sq_head;
        uint32_t *sq_tail;
        uint32_t *sq_flags;
        uint32_t sq_mask;
        uint32_t sq_entries;
        /* The SQEs between the kernel's SQ tail and sqe_tail are filled in, but not submitted yet. */
        uint32_t sqe_tail;

        struct io_uring_sqe *sqes;
        size_t sqes_size;

        uint32_t *cq_head;
        uint32_t *cq_tail;
        uint32_t cq_mask;
        struct io_uring_cqe *cqes;
} IoUring;

#define IO_URING_NULL (IoUring) { .ring_fd = -EBADF }

int io_uring_init(IoUring *ring, unsigned entries, unsigned flags);
void io_uring_done(IoUring *ring);

static inline bool io_uring_is_initialized(const IoUring *ring) {
        return ring->ring_fd >= 0;
}

struct io_uring_sqe* io_uring_get_sqe(IoUring *ring);
int io_uring_submit(IoUring *ring);

static inline uint32_t io_uring_cq_tail(const IoUring *ring) {
        /* The acquire load pairs with the release store of the kernel, so the CQEs before the tail are
         * fully written when we read them. */
        return __atomic_load_n(ring->cq_tail, __ATOMIC_ACQUIRE);
}

static inline unsigned io_uring_cq_ready(const IoUring *ring) {
        return io_uring_cq_tail(ring) - *ring->cq_head;
}

/* The kernel only reuses the slots of CQEs that io_uring_cq_advance() released. Call it after the loop
 * with the number of CQEs that the loop processed. */
#define IO_URING_FOREACH_CQE(cqe, ring)                                                         \
        _IO_URING_FOREACH_CQE(cqe, ring, UNIQ_T(head, UNIQ), UNIQ_T(tail, UNIQ))
#define _IO_URING_FOREACH_CQE(cqe, ring, head, tail)                                            \
        for (uint32_t head = *(ring)->cq_head, tail = io_uring_cq_tail(ring);                   \
             head != tail && ((cqe) = &(ring)->cqes[head & (ring)->cq_mask], true);             \
             head++)

static inline void io_uring_cq_advance(IoUring *ring, unsigned n) {
        if (n == 0)
                return;

        /* The release store makes sure that we finished reading the CQEs before the kernel overwrites
         * them. */
        __atomic_store_n(ring->cq_head, *ring->cq_head + n, __ATOMIC_RELEASE);
}

static inline void io_uring_sqe_set_data(struct io_uring_sqe *sqe, void *data) {
        sqe->user_data = (uint64_t) (uintptr_t) data;
}

static inline void* io_uring_cqe_get_data(const struct io_uring_cqe *cqe) {
        return (void*) (uintptr_t) cqe->user_data;
}

static inline void io_uring_prep_rw(
                struct io_uring_sqe *sqe,
                uint8_t opcode,
                int fd,
                const void *addr,
                uint32_t len,
                uint64_t offset) {

        sqe->opcode = opcode;
        sqe->fd = fd;
        sqe->addr = (uint64_t) (uintptr_t) addr;
        sqe->len = len;
        sqe->off = offset;
}

static inline void io_uring_prep_nop(struct io_uring_sqe *sqe) {
        io_uring_prep_rw(sqe, IORING_OP_NOP, -EBADF, NULL, 0, 0);
}

static inline void io_uring_prep_poll_add(struct io_uring_sqe *sqe, int fd, uint32_t events) {
        io_uring_prep_rw(sqe, IORING_OP_POLL_ADD, fd, NULL, 0, 0);
#if __BYTE_ORDER == __BIG_ENDIAN
        /* The kernel swaps the two 16-bit halves of poll32_events on big-endian machines, to stay
         * compatible with the old 16-bit poll_events field. */
        events = (events << 16) | (events >> 16);
#endif
        sqe->poll32_events = events;
}

static inline void io_uring_prep_poll_multishot(struct io_uring_sqe *sqe, int fd, uint32_t events) {
        io_uring_prep_poll_add(sqe, fd, events);
        sqe->len = IORING_POLL_ADD_MULTI;
}

static inline void io_uring_prep_cancel(struct io_uring_sqe *sqe, const void *user_data, uint32_t flags) {
        io_uring_prep_rw(sqe, IORING_OP_ASYNC_CANCEL, -EBADF, NULL, 0, 0);
        sqe->addr = (uint64_t) (uintptr_t) user_data;
        sqe->cancel_flags = flags;
}

static inline void io_uring_prep_read(struct io_uring_sqe *sqe, int fd, void *buf, uint32_t n, uint64_t offset) {
        io_uring_prep_rw(sqe, IORING_OP_READ, fd, buf, n, offset);
}

static inline void io_uring_prep_write(struct io_uring_sqe *sqe, int fd, const void *buf, uint32_t n, uint64_t offset) {
        io_uring_prep_rw(sqe, IORING_OP_WRITE, fd, buf, n, offset);
}

static inline void io_uring_prep_readv(struct io_uring_sqe *sqe, int fd, const struct iovec *iov, uint32_t n_iov, uint64_t offset) {
        io_uring_prep_rw(sqe, IORING_OP_READV, fd, iov, n_iov, offset);
}

static inline void io_uring_prep_writev(struct io_uring_sqe *sqe, int fd, const struct iovec *iov, uint32_t n_iov, uint64_t offset) {
        io_uring_prep_rw(sqe, IORING_OP_WRITEV, fd, iov, n_iov, offset);
}

static inline void io_uring_prep_recv(struct io_uring_sqe *sqe, int fd, void *buf, uint32_t n, int flags) {
        io_uring_prep_rw(sqe, IORING_OP_RECV, fd, buf, n, 0);
        sqe->msg_flags = (uint32_t) flags;
}

static inline void io_uring_prep_send(struct io_uring_sqe *sqe, int fd, const void *buf, uint32_t n, int flags) {
        io_uring_prep_rw(sqe, IORING_OP_SEND, fd, buf, n, 0);
        sqe->msg_flags = (uint32_t) flags;
}

static inline void io_uring_prep_recvmsg(struct io_uring_sqe *sqe, int fd, struct msghdr *msg, int flags) {
        io_uring_prep_rw(sqe, IORING_OP_RECVMSG, fd, msg, 1, 0);
        sqe->msg_flags = (uint32_t) flags;
}

static inline void io_uring_prep_sendmsg(struct io_uring_sqe *sqe, int fd, const struct msghdr *msg, int flags) {
        io_uring_prep_rw(sqe, IORING_OP_SENDMSG, fd, msg, 1, 0);
        sqe->msg_flags = (uint32_t) flags;
}

static inline void io_uring_prep_connect(struct io_uring_sqe *sqe, int fd, const struct sockaddr *addr, socklen_t addrlen) {
        io_uring_prep_rw(sqe, IORING_OP_CONNECT, fd, addr, 0, addrlen);
}

static inline void io_uring_prep_accept(struct io_uring_sqe *sqe, int fd, struct sockaddr *addr, socklen_t *addrlen, int flags) {
        io_uring_prep_rw(sqe, IORING_OP_ACCEPT, fd, addr, 0, (uint64_t) (uintptr_t) addrlen);
        sqe->accept_flags = (uint32_t) flags;
}
