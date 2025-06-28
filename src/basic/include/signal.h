/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <signal.h>

/* signal.h includes unistd.h through bits/sigstksz.h since glibc-2.34. */
#include <unistd.h>
