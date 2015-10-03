/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2015 Tom Gundersen

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

#include "util.h"
#include "siphash24.h"

#define ITERATIONS 10000000ULL

/* see https://131002.net/siphash/siphash.pdf, Appendix A */
int main(int argc, char *argv[]) {
        const uint8_t in[15]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e };
        const uint8_t key[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
        uint64_t out = 0;
        unsigned k;
        usec_t ts;

        siphash24((uint8_t *)&out, in, sizeof(in), key);

        assert_se(out == 0xa129ca6149be45e5ULL);

        ts = now(CLOCK_MONOTONIC);
        for (k = 0; k < ITERATIONS; k++)
                siphash24((uint8_t *)&out, in, sizeof(in), key);
        ts = now(CLOCK_MONOTONIC) - ts;

        log_info("%llu iterations per second", (ITERATIONS * USEC_PER_SEC) / ts);
}
