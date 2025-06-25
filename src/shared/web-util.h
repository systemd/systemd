/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

bool http_url_is_valid(const char *url) _pure_;
bool file_url_is_valid(const char *url) _pure_;

bool documentation_url_is_valid(const char *url) _pure_;

bool http_etag_is_valid(const char *etag);
