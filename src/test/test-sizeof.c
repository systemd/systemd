/***
  This file is part of systemd.

  Copyright 2016 Zbigniew Jędrzejewski-Szmek

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

#include "log.h"
#include "time-util.h"

/* Print information about various types. Useful when diagnosing
 * gcc diagnostics on an unfamiliar architecture. */

#pragma GCC diagnostic ignored "-Wtype-limits"

#define info(t)                                                 \
        log_info("%s → %zu bits%s", STRINGIFY(t),               \
                 sizeof(t)*CHAR_BIT,                            \
                 strstr(STRINGIFY(t), "signed") ? "" :          \
                 ((t)-1 < (t)0 ? ", signed" : ", unsigned"));

int main(void) {
        info(char);
        info(signed char);
        info(unsigned char);
        info(short unsigned);
        info(unsigned);
        info(long unsigned);
        info(long long unsigned);

        info(float);
        info(double);
        info(long double);

        info(size_t);
        info(ssize_t);
        info(time_t);
        info(usec_t);

        return 0;
}
