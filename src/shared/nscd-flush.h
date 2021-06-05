/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#if ENABLE_NSCD
int nscd_flush_cache(char **databases);
#else
static inline void nscd_flush_cache(char **databases) {}
#endif
