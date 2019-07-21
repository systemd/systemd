/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

int time_get_dst(time_t date, const char *tzfile,
                 time_t *switch_cur, char **zone_cur, bool *dst_cur,
                 time_t *switch_next, int *delta_next, char **zone_next, bool *dst_next);
