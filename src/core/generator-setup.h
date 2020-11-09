/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "path-lookup.h"

int lookup_paths_mkdir_generator(LookupPaths *p);
void lookup_paths_trim_generator(LookupPaths *p);
void lookup_paths_flush_generator(LookupPaths *p);
