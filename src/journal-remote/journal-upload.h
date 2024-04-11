/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include <inttypes.h>

#include "sd-event.h"
#include "sd-journal.h"

#include "time-util.h"

typedef enum {
        ENTRY_CURSOR = 0,           /* Nothing actually written yet. */
        ENTRY_REALTIME,
        ENTRY_MONOTONIC,
        ENTRY_BOOT_ID,
        ENTRY_NEW_FIELD,            /* In between fields. */
        ENTRY_TEXT_FIELD,           /* In the middle of a text field. */
        ENTRY_BINARY_FIELD_START,   /* Writing the name of a binary field. */
        ENTRY_BINARY_FIELD_SIZE,    /* Writing the size of a binary field. */
        ENTRY_BINARY_FIELD,         /* In the middle of a binary field. */
        ENTRY_OUTRO,                /* Writing '\n' */
        ENTRY_DONE,                 /* Need to move to a new field. */
} entry_state;

typedef struct Uploader {
        sd_event *events;

        char *url;
        CURL *easy;
        bool uploading;
        char error[CURL_ERROR_SIZE];
        struct curl_slist *header;
        char *answer;

        sd_event_source *input_event;
        uint64_t timeout;

        /* fd stuff */
        int input;

        /* journal stuff */
        sd_journal* journal;

        entry_state entry_state;
        const void *field_data;
        size_t field_pos, field_length;

        /* general metrics */
        const char *state_file;

        size_t entries_sent;
        char *last_cursor, *current_cursor;
        usec_t watchdog_timestamp;
        usec_t watchdog_usec;
} Uploader;

#define JOURNAL_UPLOAD_POLL_TIMEOUT (10 * USEC_PER_SEC)

int start_upload(Uploader *u,
                 size_t (*input_callback)(void *ptr,
                                          size_t size,
                                          size_t nmemb,
                                          void *userdata),
                 void *data);

int open_journal_for_upload(Uploader *u,
                            sd_journal *j,
                            const char *cursor,
                            bool after_cursor,
                            bool follow);
void close_journal_input(Uploader *u);
int check_journal_input(Uploader *u);
