/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2014 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <sys/types.h>
#include <curl/curl.h>

#include "hashmap.h"
#include "sd-event.h"

typedef struct CurlGlue CurlGlue;

struct CurlGlue {
        sd_event *event;
        CURLM *curl;
        sd_event_source *timer;
        Hashmap *ios;
        Hashmap *translate_fds;

        void (*on_finished)(CurlGlue *g, CURL *curl, CURLcode code);
        void *userdata;
};

int curl_glue_new(CurlGlue **glue, sd_event *event);
CurlGlue* curl_glue_unref(CurlGlue *glue);

DEFINE_TRIVIAL_CLEANUP_FUNC(CurlGlue*, curl_glue_unref);

int curl_glue_make(CURL **ret, const char *url, void *userdata);
int curl_glue_add(CurlGlue *g, CURL *c);
void curl_glue_remove_and_free(CurlGlue *g, CURL *c);

struct curl_slist *curl_slist_new(const char *first, ...) _sentinel_;
int curl_header_strdup(const void *contents, size_t sz, const char *field, char **value);
int curl_parse_http_time(const char *t, usec_t *ret);

DEFINE_TRIVIAL_CLEANUP_FUNC(CURL*, curl_easy_cleanup);
DEFINE_TRIVIAL_CLEANUP_FUNC(struct curl_slist*, curl_slist_free_all);
