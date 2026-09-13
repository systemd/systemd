/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

bool http_url_is_valid(const char *url) _pure_;
bool file_url_is_valid(const char *url) _pure_;
bool documentation_url_is_valid(const char *url) _pure_;

/* Our own "provider:[/path/to/socket]/resource" URL scheme, for acquiring resources from local Varlink services */
int provider_url_parse(const char *url, char **ret_socket, char **ret_resource);
bool provider_url_is_valid(const char *url) _pure_;
bool http_header_valid(const char *header) _pure_;
bool http_etag_is_valid(const char *etag) _pure_;
