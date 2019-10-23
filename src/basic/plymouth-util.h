/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#define PLYMOUTH_SOCKET {                                       \
                .un.sun_family = AF_UNIX,                       \
                .un.sun_path = "\0/org/freedesktop/plymouthd",  \
        }
