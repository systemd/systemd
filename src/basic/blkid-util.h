/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering
***/

#if HAVE_BLKID
#include <blkid.h>
#endif

#include "util.h"

#if HAVE_BLKID
DEFINE_TRIVIAL_CLEANUP_FUNC(blkid_probe, blkid_free_probe);
#define _cleanup_blkid_free_probe_ _cleanup_(blkid_free_probep)
#endif
