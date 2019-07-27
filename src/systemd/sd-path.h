/* SPDX-License-Identifier: LGPL-2.1+ */
#ifndef foosdpathhfoo
#define foosdpathhfoo

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

#include <inttypes.h>

#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

enum {
        /* Temporary files */
        SD_PATH_TEMPORARY,
        SD_PATH_TEMPORARY_LARGE,

        /* Vendor supplied data */
        SD_PATH_SYSTEM_BINARIES,
        SD_PATH_SYSTEM_INCLUDE,
        SD_PATH_SYSTEM_LIBRARY_PRIVATE,
        SD_PATH_SYSTEM_LIBRARY_ARCH,
        SD_PATH_SYSTEM_SHARED,
        SD_PATH_SYSTEM_CONFIGURATION_FACTORY,
        SD_PATH_SYSTEM_STATE_FACTORY,

        /* System configuration, runtime, state, ... */
        SD_PATH_SYSTEM_CONFIGURATION,
        SD_PATH_SYSTEM_RUNTIME,
        SD_PATH_SYSTEM_RUNTIME_LOGS,
        SD_PATH_SYSTEM_STATE_PRIVATE,
        SD_PATH_SYSTEM_STATE_LOGS,
        SD_PATH_SYSTEM_STATE_CACHE,
        SD_PATH_SYSTEM_STATE_SPOOL,

        /* Vendor supplied data */
        SD_PATH_USER_BINARIES,
        SD_PATH_USER_LIBRARY_PRIVATE,
        SD_PATH_USER_LIBRARY_ARCH,
        SD_PATH_USER_SHARED,

        /* User configuration, state, runtime ... */
        SD_PATH_USER_CONFIGURATION, /* takes both actual configuration (like /etc) and state (like /var/lib) */
        SD_PATH_USER_RUNTIME,
        SD_PATH_USER_STATE_CACHE,

        /* User resources */
        SD_PATH_USER, /* $HOME itself */
        SD_PATH_USER_DOCUMENTS,
        SD_PATH_USER_MUSIC,
        SD_PATH_USER_PICTURES,
        SD_PATH_USER_VIDEOS,
        SD_PATH_USER_DOWNLOAD,
        SD_PATH_USER_PUBLIC,
        SD_PATH_USER_TEMPLATES,
        SD_PATH_USER_DESKTOP,

        /* Search paths */
        SD_PATH_SEARCH_BINARIES,
        SD_PATH_SEARCH_BINARIES_DEFAULT,
        SD_PATH_SEARCH_LIBRARY_PRIVATE,
        SD_PATH_SEARCH_LIBRARY_ARCH,
        SD_PATH_SEARCH_SHARED,
        SD_PATH_SEARCH_CONFIGURATION_FACTORY,
        SD_PATH_SEARCH_STATE_FACTORY,
        SD_PATH_SEARCH_CONFIGURATION,

        _SD_PATH_MAX,
};

int sd_path_home(uint64_t type, const char *suffix, char **path);
int sd_path_search(uint64_t type, const char *suffix, char ***paths);

_SD_END_DECLARATIONS;

#endif
