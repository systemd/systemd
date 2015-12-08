/***
  This file is part of systemd

  Copyright 2014 Tom Gundersen

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

#include "sparse-endian.h"
#include "unaligned.h"
#include "util.h"

static uint8_t data[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

static void test_be(void) {
        uint8_t scratch[16];

        assert_se(unaligned_read_be16(&data[0]) == 0x0001);
        assert_se(unaligned_read_be16(&data[1]) == 0x0102);

        assert_se(unaligned_read_be32(&data[0]) == 0x00010203);
        assert_se(unaligned_read_be32(&data[1]) == 0x01020304);
        assert_se(unaligned_read_be32(&data[2]) == 0x02030405);
        assert_se(unaligned_read_be32(&data[3]) == 0x03040506);

        assert_se(unaligned_read_be64(&data[0]) == 0x0001020304050607);
        assert_se(unaligned_read_be64(&data[1]) == 0x0102030405060708);
        assert_se(unaligned_read_be64(&data[2]) == 0x0203040506070809);
        assert_se(unaligned_read_be64(&data[3]) == 0x030405060708090a);
        assert_se(unaligned_read_be64(&data[4]) == 0x0405060708090a0b);
        assert_se(unaligned_read_be64(&data[5]) == 0x05060708090a0b0c);
        assert_se(unaligned_read_be64(&data[6]) == 0x060708090a0b0c0d);
        assert_se(unaligned_read_be64(&data[7]) == 0x0708090a0b0c0d0e);

        zero(scratch);
        unaligned_write_be16(&scratch[0], 0x0001);
        assert_se(memcmp(&scratch[0], &data[0], sizeof(uint16_t)) == 0);
        zero(scratch);
        unaligned_write_be16(&scratch[1], 0x0102);
        assert_se(memcmp(&scratch[1], &data[1], sizeof(uint16_t)) == 0);

        zero(scratch);
        unaligned_write_be32(&scratch[0], 0x00010203);
        assert_se(memcmp(&scratch[0], &data[0], sizeof(uint32_t)) == 0);
        zero(scratch);
        unaligned_write_be32(&scratch[1], 0x01020304);
        assert_se(memcmp(&scratch[1], &data[1], sizeof(uint32_t)) == 0);
        zero(scratch);
        unaligned_write_be32(&scratch[2], 0x02030405);
        assert_se(memcmp(&scratch[2], &data[2], sizeof(uint32_t)) == 0);
        zero(scratch);
        unaligned_write_be32(&scratch[3], 0x03040506);
        assert_se(memcmp(&scratch[3], &data[3], sizeof(uint32_t)) == 0);

        zero(scratch);
        unaligned_write_be64(&scratch[0], 0x0001020304050607);
        assert_se(memcmp(&scratch[0], &data[0], sizeof(uint64_t)) == 0);
        zero(scratch);
        unaligned_write_be64(&scratch[1], 0x0102030405060708);
        assert_se(memcmp(&scratch[1], &data[1], sizeof(uint64_t)) == 0);
        zero(scratch);
        unaligned_write_be64(&scratch[2], 0x0203040506070809);
        assert_se(memcmp(&scratch[2], &data[2], sizeof(uint64_t)) == 0);
        zero(scratch);
        unaligned_write_be64(&scratch[3], 0x030405060708090a);
        assert_se(memcmp(&scratch[3], &data[3], sizeof(uint64_t)) == 0);
        zero(scratch);
        unaligned_write_be64(&scratch[4], 0x0405060708090a0b);
        assert_se(memcmp(&scratch[4], &data[4], sizeof(uint64_t)) == 0);
        zero(scratch);
        unaligned_write_be64(&scratch[5], 0x05060708090a0b0c);
        assert_se(memcmp(&scratch[5], &data[5], sizeof(uint64_t)) == 0);
        zero(scratch);
        unaligned_write_be64(&scratch[6], 0x060708090a0b0c0d);
        assert_se(memcmp(&scratch[6], &data[6], sizeof(uint64_t)) == 0);
        zero(scratch);
        unaligned_write_be64(&scratch[7], 0x0708090a0b0c0d0e);
        assert_se(memcmp(&scratch[7], &data[7], sizeof(uint64_t)) == 0);
}

static void test_le(void) {
        uint8_t scratch[16];

        assert_se(unaligned_read_le16(&data[0]) == 0x0100);
        assert_se(unaligned_read_le16(&data[1]) == 0x0201);

        assert_se(unaligned_read_le32(&data[0]) == 0x03020100);
        assert_se(unaligned_read_le32(&data[1]) == 0x04030201);
        assert_se(unaligned_read_le32(&data[2]) == 0x05040302);
        assert_se(unaligned_read_le32(&data[3]) == 0x06050403);

        assert_se(unaligned_read_le64(&data[0]) == 0x0706050403020100);
        assert_se(unaligned_read_le64(&data[1]) == 0x0807060504030201);
        assert_se(unaligned_read_le64(&data[2]) == 0x0908070605040302);
        assert_se(unaligned_read_le64(&data[3]) == 0x0a09080706050403);
        assert_se(unaligned_read_le64(&data[4]) == 0x0b0a090807060504);
        assert_se(unaligned_read_le64(&data[5]) == 0x0c0b0a0908070605);
        assert_se(unaligned_read_le64(&data[6]) == 0x0d0c0b0a09080706);
        assert_se(unaligned_read_le64(&data[7]) == 0x0e0d0c0b0a090807);

        zero(scratch);
        unaligned_write_le16(&scratch[0], 0x0100);
        assert_se(memcmp(&scratch[0], &data[0], sizeof(uint16_t)) == 0);
        zero(scratch);
        unaligned_write_le16(&scratch[1], 0x0201);
        assert_se(memcmp(&scratch[1], &data[1], sizeof(uint16_t)) == 0);

        zero(scratch);
        unaligned_write_le32(&scratch[0], 0x03020100);

        assert_se(memcmp(&scratch[0], &data[0], sizeof(uint32_t)) == 0);
        zero(scratch);
        unaligned_write_le32(&scratch[1], 0x04030201);
        assert_se(memcmp(&scratch[1], &data[1], sizeof(uint32_t)) == 0);
        zero(scratch);
        unaligned_write_le32(&scratch[2], 0x05040302);
        assert_se(memcmp(&scratch[2], &data[2], sizeof(uint32_t)) == 0);
        zero(scratch);
        unaligned_write_le32(&scratch[3], 0x06050403);
        assert_se(memcmp(&scratch[3], &data[3], sizeof(uint32_t)) == 0);

        zero(scratch);
        unaligned_write_le64(&scratch[0], 0x0706050403020100);
        assert_se(memcmp(&scratch[0], &data[0], sizeof(uint64_t)) == 0);
        zero(scratch);
        unaligned_write_le64(&scratch[1], 0x0807060504030201);
        assert_se(memcmp(&scratch[1], &data[1], sizeof(uint64_t)) == 0);
        zero(scratch);
        unaligned_write_le64(&scratch[2], 0x0908070605040302);
        assert_se(memcmp(&scratch[2], &data[2], sizeof(uint64_t)) == 0);
        zero(scratch);
        unaligned_write_le64(&scratch[3], 0x0a09080706050403);
        assert_se(memcmp(&scratch[3], &data[3], sizeof(uint64_t)) == 0);
        zero(scratch);
        unaligned_write_le64(&scratch[4], 0x0B0A090807060504);
        assert_se(memcmp(&scratch[4], &data[4], sizeof(uint64_t)) == 0);
        zero(scratch);
        unaligned_write_le64(&scratch[5], 0x0c0b0a0908070605);
        assert_se(memcmp(&scratch[5], &data[5], sizeof(uint64_t)) == 0);
        zero(scratch);
        unaligned_write_le64(&scratch[6], 0x0d0c0b0a09080706);
        assert_se(memcmp(&scratch[6], &data[6], sizeof(uint64_t)) == 0);
        zero(scratch);
        unaligned_write_le64(&scratch[7], 0x0e0d0c0b0a090807);
        assert_se(memcmp(&scratch[7], &data[7], sizeof(uint64_t)) == 0);
}

int main(int argc, const char *argv[]) {
        test_be();
        test_le();
}
