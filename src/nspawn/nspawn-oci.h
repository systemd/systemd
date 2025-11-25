/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"
#include "nspawn-settings.h"

int oci_load(FILE *f, const char *bundle, Settings **ret);
