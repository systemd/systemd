/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef foosdfuturefoo
#define foosdfuturefoo

/***
  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <https://www.gnu.org/licenses/>.
***/

#include <sys/signal.h>

#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

enum {
        SD_FUTURE_IO,
        SD_FUTURE_TIME,
        SD_FUTURE_CHILD,
        SD_FUTURE_BUS,
};

enum {
        SD_FUTURE_PENDING,
        SD_FUTURE_READY,
}

_SD_END_DECLARATIONS;

#endif
