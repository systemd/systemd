/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

char* bus_label_escape(const char *s);
char* bus_label_unescape_n(const char *f, size_t l);

char* bus_label_unescape(const char *f);
