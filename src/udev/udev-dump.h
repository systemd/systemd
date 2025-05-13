/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include "udev-forward.h"

void event_cache_written_sysattr(UdevEvent *event, const char *attr, const char *value);
void event_cache_written_sysctl(UdevEvent *event, const char *attr, const char *value);
int dump_event(UdevEvent *event, sd_json_format_flags_t flags, FILE *f);
