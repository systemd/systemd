/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>

#include "parse-util.h"
#include "time-util.h"

typedef enum PressureType {
        PRESSURE_TYPE_SOME,
        PRESSURE_TYPE_FULL,
} PressureType;

/* Averages are stored in fixed-point with 11 bit fractions */
typedef struct ResourcePressure {
        loadavg_t avg10;
        loadavg_t avg60;
        loadavg_t avg300;
        usec_t total;
} ResourcePressure;

/** Upstream 4.20+ format
 *
 *  some avg10=0.22 avg60=0.17 avg300=1.11 total=58761459
 *  full avg10=0.23 avg60=0.16 avg300=1.08 total=58464525
 */
int read_resource_pressure(const char *path, PressureType type, ResourcePressure *ret);

/* Was the kernel compiled with CONFIG_PSI=y? 1 if yes, 0 if not, negative on error. */
int is_pressure_supported(void);
