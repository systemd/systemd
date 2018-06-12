/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  Copyright 2010 Lennart Poettering
***/

#include <stdbool.h>

#include "macro.h"

bool http_url_is_valid(const char *url) _pure_;

bool documentation_url_is_valid(const char *url) _pure_;

bool http_etag_is_valid(const char *etag);
