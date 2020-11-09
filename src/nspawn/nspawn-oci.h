/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "nspawn-settings.h"

int oci_load(FILE *f, const char *path, Settings **ret);
