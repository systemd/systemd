/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/coredump.h>
#include <unistd.h>

#include "copy.h"
#include "coredump-records.h"
#include "io-util.h"
#include "log.h"

/* Returns 1 if a header was read, 0 if the stream ended before a complete header. */
static int read_record_header(int fd, struct coredump_record_header *ret) {
        struct coredump_record_header h = {};
        ssize_t n;

        assert(fd >= 0);
        assert(ret);

        /* The size comes first, so that the kernel can grow the header later. */
        n = loop_read(fd, &h.size, sizeof(h.size), /* do_poll= */ true);
        if (n < 0)
                return (int) n;
        if ((size_t) n != sizeof(h.size))
                return 0;
        if (h.size < COREDUMP_RECORD_HEADER_SIZE_VER0)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                       "Coredump record header is too small (%"PRIu32" < %i).",
                                       h.size, COREDUMP_RECORD_HEADER_SIZE_VER0);

        size_t k = MIN((size_t) h.size, sizeof(h)) - sizeof(h.size);
        n = loop_read(fd, (uint8_t*) &h + sizeof(h.size), k, /* do_poll= */ true);
        if (n < 0)
                return (int) n;
        if ((size_t) n != k)
                return 0;

        /* Discard the fields of a newer, larger header that we don't know. */
        for (size_t left = h.size - MIN((size_t) h.size, sizeof(h)); left > 0;) {
                uint8_t buf[64];

                n = loop_read(fd, buf, MIN(left, sizeof(buf)), /* do_poll= */ true);
                if (n < 0)
                        return (int) n;
                if (n == 0)
                        return 0;

                left -= n;
        }

        *ret = h;
        return 1;
}

/* Writes a coredump that the kernel sends as records (COREDUMP_RECORDS) to output_fd, at most max_size
 * bytes of it. Zero records (COREDUMP_SPARSE) become holes, so the zeros are neither transferred nor
 * written. Returns 0 if the whole coredump was written, 1 if it was truncated to max_size or the kernel
 * didn't send an end record, and a negative errno on failure. */
int coredump_copy_records(int input_fd, int output_fd, uint64_t max_size) {
        uint64_t offset = 0; /* coredump bytes covered by the records so far */
        bool truncated = false;
        int r;

        assert(input_fd >= 0);
        assert(output_fd >= 0);

        for (;;) {
                struct coredump_record_header h;

                r = read_record_header(input_fd, &h);
                if (r < 0)
                        return r;
                if (r == 0) {
                        log_warning("Coredump ended without an end record, it is incomplete.");
                        truncated = true;
                        break;
                }

                if (h.flags != 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "Coredump record has unknown flags (%"PRIx64").",
                                               (uint64_t) h.flags);
                if (h.offset != offset)
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "Coredump record starts at %"PRIu64", expected %"PRIu64".",
                                               (uint64_t) h.offset, offset);
                if (h.len > INT64_MAX - offset)
                        return log_debug_errno(SYNTHETIC_ERRNO(EFBIG),
                                               "Coredump record of %"PRIu64" bytes at %"PRIu64" is too large.",
                                               (uint64_t) h.len, offset);

                if (h.type == COREDUMP_RECORD_END) {
                        if (h.len != 0)
                                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                                       "Coredump end record has non-zero length (%"PRIu64").",
                                                       (uint64_t) h.len);
                        break;
                }
                if (!IN_SET(h.type, COREDUMP_RECORD_DATA, COREDUMP_RECORD_ZERO))
                        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG),
                                               "Coredump record has unknown type (%"PRIu32").", h.type);

                uint64_t n = MIN((uint64_t) h.len, LESS_BY(max_size, offset));

                if (h.type == COREDUMP_RECORD_DATA) {
                        r = copy_bytes(input_fd, output_fd, n, /* copy_flags= */ 0);
                        if (r < 0)
                                return r;
                        if (r == 0) {
                                log_warning("Coredump ended in the middle of a data record, it is incomplete.");
                                truncated = true;
                                break;
                        }
                } else if (n > 0 && lseek(output_fd, (off_t) n, SEEK_CUR) < 0)
                        return -errno;

                offset += h.len;

                if (n < h.len) {
                        /* Reached max_size. The rest is not read, the caller closes the socket. */
                        truncated = true;
                        break;
                }
        }

        /* A hole at the end only becomes part of the file once the file size covers it. */
        off_t end = lseek(output_fd, 0, SEEK_CUR);
        if (end < 0)
                return -errno;
        if (ftruncate(output_fd, end) < 0)
                return -errno;

        return truncated;
}
