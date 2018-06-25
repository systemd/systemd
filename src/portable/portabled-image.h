/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "hashmap.h"
#include "machine-image.h"
#include "portabled.h"

Image *manager_image_cache_get(Manager *m, const char *name_or_path);

int manager_image_cache_add(Manager *m, Image *image);

int manager_image_cache_discover(Manager *m, Hashmap *images, sd_bus_error *error);
