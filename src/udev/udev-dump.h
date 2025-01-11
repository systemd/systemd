/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include <stdio.h>

typedef struct UdevEvent UdevEvent;

void event_cache_written_sysattr(UdevEvent *event, const char *attr, const char *value);
void event_cache_written_sysctl(UdevEvent *event, const char *attr, const char *value);
void dump_event(UdevEvent *event, FILE *f);
