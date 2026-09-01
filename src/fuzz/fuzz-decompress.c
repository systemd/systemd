/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "compress.h"
#include "fd-util.h"
#include "fuzz.h"
#include "memfd-util.h"
#include "memory-util.h"

/* Unlike fuzz-compress, which round-trips data through a compressor and thus only ever hands the
 * decoders well-formed input, this feeds arbitrary bytes straight to the decompression entrypoints.
 * That is the situation the decoders are actually in: the blobs they parse come from journal files,
 * systemd-journal-remote streams and coredumps, i.e. from wherever the data was written, which is not
 * necessarily somewhere we trust. */

/* Cap the output so that a decompression bomb doesn't OOM the fuzzer: we are looking for memory errors
 * in the decoders, not for their willingness to allocate. */
#define DST_MAX_LIMIT (2U * 1024U * 1024U)

typedef enum EntryPoint {
        ENTRYPOINT_BLOB,
        ENTRYPOINT_STARTSWITH,
        ENTRYPOINT_STREAM,
        ENTRYPOINT_PUSH,
        _ENTRYPOINT_MAX,
} EntryPoint;

typedef struct PushState {
        uint64_t written;
        uint64_t limit;
} PushState;

static int push_callback(const void *data, size_t size, void *userdata) {
        PushState *s = ASSERT_PTR(userdata);

        /* Same reasoning as for DST_MAX_LIMIT: stop the decode once enough came out, rather than let a
         * bomb run to completion. */
        s->written += size;
        if (s->written > s->limit)
                return -EFBIG;

        return 0;
}

typedef struct header {
        uint8_t entrypoint;
        uint8_t extra;
        uint16_t prefix_len;
        uint8_t reserved[8]; /* Extra space to keep fuzz cases stable in case we need to add stuff in the
                              * future. */
        uint32_t dst_max;
        uint8_t data[];
} header;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        int r;

        if (size < offsetof(header, data) + 1)
                return 0;

        const header *h = (const header*) data;
        const uint8_t *blob = h->data;
        const size_t blob_size = size - offsetof(header, data);

        /* Take the algorithm from the blob rather than from the header: this is what the callers that
         * do not know it in advance use, and it keeps the corpus independent of the (internal) order of
         * the Compression enum. */
        uint8_t magic[COMPRESSION_MAGIC_BYTES_MAX] = {};
        memcpy_safe(magic, blob, MIN(blob_size, sizeof(magic)));

        Compression alg = compression_detect_from_magic(magic);
        if (alg < 0 || !compression_supported(alg))
                return 0;

        fuzz_setup_logging();

        /* Leave 0 ("no limit") out of reach: an unbounded decode of a hostile blob is a memory
         * exhaustion test, not a memory safety test. */
        size_t dst_max = (h->dst_max % DST_MAX_LIMIT) + 1;

        log_info("Using compression %s, blob size=%zu, dst_max=%zu",
                 compression_to_string(alg), blob_size, dst_max);

        switch ((EntryPoint) h->entrypoint) {

        case ENTRYPOINT_BLOB: {
                _cleanup_free_ void *buf = NULL;
                size_t dst_size;

                r = decompress_blob(alg, blob, blob_size, &buf, &dst_size, dst_max);
                if (r < 0)
                        log_debug_errno(r, "decompress_blob() failed: %m");
                else
                        log_debug("Decompressed %zu bytes to → %zu bytes", blob_size, dst_size);
                break;
        }

        case ENTRYPOINT_STARTSWITH: {
                _cleanup_free_ void *buf = NULL;

                /* Compare against a prefix taken from the blob itself, so that a match is at least
                 * reachable rather than astronomically unlikely. */
                size_t prefix_len = MIN((size_t) h->prefix_len, blob_size);

                r = decompress_startswith(alg, blob, blob_size, &buf, blob, prefix_len, h->extra);
                if (r < 0)
                        log_debug_errno(r, "decompress_startswith() failed: %m");
                else
                        log_debug("Prefix of %zu bytes %s", prefix_len, r > 0 ? "matches" : "does not match");
                break;
        }

        case ENTRYPOINT_STREAM: {
                _cleanup_close_ int fd = -EBADF, null_fd = -EBADF;
                ssize_t n;

                fd = memfd_new_and_seal("fuzz-decompress", blob, blob_size);
                if (fd < 0) {
                        log_debug_errno(fd, "Failed to allocate memfd, skipping: %m");
                        return 0;
                }

                n = lseek(fd, 0, SEEK_SET);
                if (n < 0)
                        return 0;

                null_fd = open("/dev/null", O_WRONLY|O_CLOEXEC|O_NOCTTY);
                if (null_fd < 0)
                        return 0;

                (void) decompress_stream(alg, fd, null_fd, dst_max);
                break;
        }

        case ENTRYPOINT_PUSH: {
                /* This is the path systemd-importd takes for downloaded images: sniff the compression
                 * off the first bytes, then push the stream in as it arrives off the network, and
                 * finally push a zero-length chunk to finalize. Feed it in chunks so that the decoders
                 * see the same fragmentation a real download produces. */
                _cleanup_(compressor_freep) Decompressor *d = NULL;
                PushState state = { .limit = dst_max };

                r = decompressor_detect(&d, blob, blob_size);
                if (r <= 0)
                        break;

                size_t chunk = (h->prefix_len % 4096) + 1;
                for (size_t o = 0; o < blob_size; o += chunk) {
                        r = decompressor_push(d, blob + o, MIN(chunk, blob_size - o), push_callback, &state);
                        if (r < 0)
                                break;
                }
                if (r >= 0)
                        (void) decompressor_push(d, /* data= */ NULL, /* size= */ 0, push_callback, &state);
                break;
        }

        default:
                log_debug("Unknown entry point %u, skipping.", h->entrypoint);
        }

        return 0;
}
