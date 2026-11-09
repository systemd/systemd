/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

bool http_url_is_valid(const char *url) _pure_;
bool file_url_is_valid(const char *url) _pure_;
bool documentation_url_is_valid(const char *url) _pure_;

/* Our own "provider:[/path/to/socket]/resource" URL scheme, for acquiring resources from local Varlink services */
int provider_url_parse(const char *url, char **ret_socket, char **ret_resource);
bool provider_url_is_valid(const char *url);
bool http_header_valid(const char *header) _pure_;
bool http_etag_is_valid(const char *etag) _pure_;

bool http_field_name_is_valid(const char *name) _pure_;
bool http_field_value_is_valid(const char *value) _pure_;
bool http_field_name_is_client_owned(const char *name) _pure_;

int http_url_get_origin(const char *url, char **ret);

/* The maximum number of additional HTTP request header fields we accept from external sources */
#define HTTP_HEADERS_MAX 64U

int http_headers_parse(FILE *f, char ***ret);
int http_headers_format(char * const *headers, char **ret);

int parse_content_range(const char *s, uint64_t *ret_start, uint64_t *ret_end, uint64_t *ret_total);
