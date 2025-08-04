/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "hashmap.h"

int fetch_batteries_capacity_by_name(Hashmap **ret_current_capacity);
int get_capacity_by_name(Hashmap *capacities_by_name, const char *name);

int get_total_suspend_interval(Hashmap *last_capacity, usec_t *ret);

int estimate_battery_discharge_rate_per_hour(
                Hashmap *last_capacity,
                Hashmap *current_capacity,
                usec_t before_timestamp,
                usec_t after_timestamp);

int battery_trip_point_alarm_exists(void);
