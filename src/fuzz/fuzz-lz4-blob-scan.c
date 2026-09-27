/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "compress.h"
#include "fuzz.h"
#include "tests.h"

/* The input to lz4_blob_scan() is split wherever network reads end, so the result must not depend on where
 * the input is split. No decoding is done, so this fuzzer does not need liblz4. */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        LZ4BlobScan whole = {}, split = {};
        size_t piece;
        int r_whole, r_split;

        if (outside_size_range(size, 1, 256 * 1024))
                return 0;

        fuzz_setup_logging();

        /* The first byte picks the size of the pieces, from 1 to 256. */
        piece = data[0] + 1U;
        data++;
        size--;

        r_whole = lz4_blob_scan(data, size, &whole);

        for (size_t n = MIN(piece, size);; n = MIN(n + piece, size)) {
                r_split = lz4_blob_scan(data, n, &split);
                if (r_split != 0 || n == size)
                        break;
        }

        ASSERT_EQ(r_split, r_whole);
        if (r_whole > 0) {
                ASSERT_EQ(split.offset, whole.offset);
                ASSERT_LE(whole.offset, size);
        }

        return 0;
}
