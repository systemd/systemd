/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

_sync_ void bus_track_dispatch(sd_bus_track *track);
_sync_ void bus_track_close(sd_bus_track *track);
