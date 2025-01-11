/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include <stdio.h>

typedef struct UdevEvent UdevEvent;

void dump_event(UdevEvent *event, FILE *f);
