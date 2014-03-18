#pragma once

#include <inttypes.h>

#include "sd-event.h"

typedef struct Uploader {
        sd_event *events;

        const char *url;
        CURL *easy;
        bool uploading;
        struct curl_slist *header;

        int input;

        sd_event_source *input_event;
} Uploader;

int start_upload(Uploader *u,
                 size_t (*input_callback)(void *ptr,
                                          size_t size,
                                          size_t nmemb,
                                          void *userdata),
                 void *data);
