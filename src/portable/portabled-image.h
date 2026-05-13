/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "portabled-forward.h"

Image *manager_image_cache_get(Manager *m, const char *name_or_path);

int manager_image_cache_add(Manager *m, Image *image);

int manager_image_cache_discover(Manager *m, Hashmap **ret_images, sd_bus_error *error);
