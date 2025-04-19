/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct sd_bus_track sd_bus_track;

void bus_track_dispatch(sd_bus_track *track);
void bus_track_close(sd_bus_track *track);
