/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  Copyright 2013 Lennart Poettering
***/

void bus_track_dispatch(sd_bus_track *track);
void bus_track_close(sd_bus_track *track);
