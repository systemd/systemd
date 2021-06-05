/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#if HAVE_BLKID
#  include <blkid.h>

#  include "macro.h"

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(blkid_probe, blkid_free_probe, NULL);
#endif
