/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <signal.h>        /* IWYU pragma: export */

#ifndef ILL_BADIADDR
#define ILL_BADIADDR 9
#endif

#ifndef FPE_FLTUNK
#define FPE_FLTUNK 14
#endif

#ifndef FPE_CONDTRAP
#define FPE_CONDTRAP 15
#endif

#ifndef SEGV_ACCADI
#define SEGV_ACCADI 5
#endif

#ifndef SEGV_ADIDERR
#define SEGV_ADIDERR 6
#endif

#ifndef SEGV_ADIPERR
#define SEGV_ADIPERR 7
#endif
