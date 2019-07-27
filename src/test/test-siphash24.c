/* SPDX-License-Identifier: LGPL-2.1+ */

#include "memory-util.h"
#include "siphash24.h"

#define ITERATIONS 10000000ULL

static void do_test(const uint8_t *in, size_t len, const uint8_t *key) {
        struct siphash state = {};
        uint64_t out;
        unsigned i, j;

        out = siphash24(in, len, key);
        assert_se(out == 0xa129ca6149be45e5);

        /* verify the internal state as given in the above paper */
        siphash24_init(&state, key);
        assert_se(state.v0 == 0x7469686173716475);
        assert_se(state.v1 == 0x6b617f6d656e6665);
        assert_se(state.v2 == 0x6b7f62616d677361);
        assert_se(state.v3 == 0x7b6b696e727e6c7b);
        siphash24_compress(in, len, &state);
        assert_se(state.v0 == 0x4a017198de0a59e0);
        assert_se(state.v1 == 0x0d52f6f62a4f59a4);
        assert_se(state.v2 == 0x634cb3577b01fd3d);
        assert_se(state.v3 == 0xa5224d6f55c7d9c8);
        out = siphash24_finalize(&state);
        assert_se(out == 0xa129ca6149be45e5);
        assert_se(state.v0 == 0xf6bcd53893fecff1);
        assert_se(state.v1 == 0x54b9964c7ea0d937);
        assert_se(state.v2 == 0x1b38329c099bb55a);
        assert_se(state.v3 == 0x1814bb89ad7be679);

        /* verify that decomposing the input in three chunks gives the
           same result */
        for (i = 0; i < len; i++) {
                for (j = i; j < len; j++) {
                        siphash24_init(&state, key);
                        siphash24_compress(in, i, &state);
                        siphash24_compress(&in[i], j - i, &state);
                        siphash24_compress(&in[j], len - j, &state);
                        out = siphash24_finalize(&state);
                        assert_se(out == 0xa129ca6149be45e5);
                }
        }
}

static void test_short_hashes(void) {
        const uint8_t one[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };
        const uint8_t  key[16] = { 0x22, 0x24, 0x41, 0x22, 0x55, 0x77, 0x88, 0x07,
                                   0x23, 0x09, 0x23, 0x14, 0x0c, 0x33, 0x0e, 0x0f};
        uint8_t two[sizeof one] = {};

        struct siphash state1 = {}, state2 = {};
        unsigned i, j;

        siphash24_init(&state1, key);
        siphash24_init(&state2, key);

        /* hashing 1, 2, 3, 4, 5, ..., 16 bytes, with the byte after the buffer different */
        for (i = 1; i <= sizeof one; i++) {
                siphash24_compress(one, i, &state1);

                two[i-1] = one[i-1];
                siphash24_compress(two, i, &state2);

                assert_se(memcmp(&state1, &state2, sizeof state1) == 0);
        }

        /* hashing n and 1, n and 2, n and 3, ..., n-1 and 1, n-2 and 2, ... */
        for (i = sizeof one; i > 0; i--) {
                zero(two);

                for (j = 1; j <= sizeof one; j++) {
                        siphash24_compress(one, i, &state1);
                        siphash24_compress(one, j, &state1);

                        siphash24_compress(one, i, &state2);
                        two[j-1] = one[j-1];
                        siphash24_compress(two, j, &state2);

                        assert_se(memcmp(&state1, &state2, sizeof state1) == 0);
                }
        }
}

/* see https://131002.net/siphash/siphash.pdf, Appendix A */
int main(int argc, char *argv[]) {
        const uint8_t in[15]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e };
        const uint8_t key[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
        uint8_t in_buf[20];

        /* Test with same input but different alignments. */
        memcpy(in_buf, in, sizeof(in));
        do_test(in_buf, sizeof(in), key);
        memcpy(in_buf + 1, in, sizeof(in));
        do_test(in_buf + 1, sizeof(in), key);
        memcpy(in_buf + 2, in, sizeof(in));
        do_test(in_buf + 2, sizeof(in), key);
        memcpy(in_buf + 4, in, sizeof(in));
        do_test(in_buf + 4, sizeof(in), key);

        test_short_hashes();
}
