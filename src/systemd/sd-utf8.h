/* SPDX-License-Identifier: LGPL-2.1+ */
#ifndef foosdutf8hfoo
#define foosdutf8hfoo

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
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

_sd_pure_ const char *sd_utf8_is_valid(const char *s);
_sd_pure_ const char *sd_ascii_is_valid(const char *s);

_SD_END_DECLARATIONS;

#endif
