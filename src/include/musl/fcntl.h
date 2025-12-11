/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <fcntl.h>

/* On musl, O_ACCMODE is defined as (03|O_SEARCH), unlike glibc which defines it as
 * (O_RDONLY|O_WRONLY|O_RDWR). Additionally, O_SEARCH is simply defined as O_PATH. This changes the behaviour
 * of O_ACCMODE in certain situations, which we don't want. This definition is copied from glibc and works
 * around the problems with musl's definition. */
#undef O_ACCMODE
#define O_ACCMODE (O_RDONLY|O_WRONLY|O_RDWR)
