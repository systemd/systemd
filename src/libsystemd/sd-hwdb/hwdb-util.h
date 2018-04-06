/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2014 Tom Gundersen <teg@jklm.no>
***/

#include "sd-hwdb.h"

#include "util.h"

bool hwdb_validate(sd_hwdb *hwdb);
