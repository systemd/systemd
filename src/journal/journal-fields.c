/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2015 Henrik Kaare Poulsen

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

/* ============================================================ */

/*
   Inspired by log-show.c
   Copyright 2012 Lennart Poettering
*/

/* ============================================================ */

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include "sd-journal.h"
#include "hashmap.h"
#include "parse-util.h"
#include "string-util.h"
#include "log.h"
#include "utf8.h"
#include "terminal-util.h"
#include "journal-internal.h"
#include "journal-fields.h"

/* ============================================================ */

/* Maximal number of distinct field values to print.
   (Does not apply if --fields=<FIELDNAME> is given).
   Remember to update in manual, if the value is changed.
*/
#define MAX_VALUES ((size_t)100)

/* When printing to tty, print the field value in at least
   this number of columns.
*/
#define MIN_COLUMNS ((size_t)20)

/* When printing to a pipe, print the field value in at least
   this number of columns.
   Remember to update in manual, if the value is changed.
*/
#define DEFAULT_COLUMNS ((size_t)1024)

/* ============================================================ */

/*
   The systemd functions returning field names and values,
   return a data array (not necessarily a null-terminated string),
   and gives the field name and field value in the same data array,
   separated with '='.

   The approach taken in log-show.c is to strncpy the values,
   before checking if they are already in a hash table.
   However, in case the value IS already in the hash table,
   the strncpy is not necessary.

   For log-show.c this is not a serious performance penalty:
   most fields will only be present once in a log entry.

   For 'journalctl --fields' and 'journalctl --fields --fields'
   most field names and many field values will be repeated,
   and hence the wasted strncpy will incur a performance penalty.

   Hence we define a new key structure called StringKey,
   which contains the length of the key, as well as the key string.

   Suitable hash and compare functions are defined and added to
   string_key_hash_ops which is similar to the old string_hash_ops.

   In general, we add entries to the hashmap with zero-terminated
   strings, but may query the hashmap whith non-zeor-terminated data.
*/

typedef struct _StringKey {
        size_t len;
        char *sz;
} StringKey;

static void string_key_hash_func(const void *p, struct siphash *state) {
        siphash24_compress(((StringKey*)p)->sz, ((StringKey*)p)->len, state);
};

static int string_key_compare_func(const void *a, const void *b) {
        int r = strncmp(((StringKey*)a)->sz, ((StringKey*)b)->sz, MIN(((StringKey*)a)->len, ((StringKey*)b)->len));
        if (r==0) { return ((StringKey*)b)->len - ((StringKey*)a)->len; }
        return r;
};

const struct hash_ops string_key_hash_ops = {
        .hash = string_key_hash_func,
        .compare = string_key_compare_func
};

/* ============================================================ */

/* A hash-table entry, which contains another hash-table
   and some counters
*/

typedef struct _HashN {
        size_t n;   /* number of entries having this field      */
        size_t nv;  /* number of distinct values for this field */
        Hashmap *h; /* hash of distinct values for this field   */
} HashN;

/* ============================================================ */

/* Put a field value (sk) into the hash of values for this field */

static int put_journal_value(HashN *hh, StringKey sk) {
        int r = 0;
        size_t nn;
        StringKey *psk;

        /* Try to find the field value in the hash */
        nn = PTR_TO_SIZE(hashmap_get(hh->h, &sk));

        if (nn == 0) {
                /* The field value was NOT found, so add it */

                hh->nv++;

                psk = malloc(sizeof(StringKey));
                if (!psk) { return -ENOMEM; }
                psk->len = sk.len;
                psk->sz = malloc(sk.len+1);
                if (!(psk->sz)) { return -ENOMEM; }
                memcpy(psk->sz, sk.sz, sk.len);
                psk->sz[sk.len] = '\0';

                r = hashmap_put(hh->h, psk, SIZE_TO_PTR(1));
                if (r < 0) { return r; }

        } else {
                /* The field value WAS found, so update the counter */

                r = hashmap_update(hh->h, &sk, SIZE_TO_PTR(nn+1));
                if (r < 0) { return r; }
        }
        return 0;
}

/* ============================================================ */

/* Handle journalctl --fields */

int journal_fields(sd_journal *j, int n, const char* field) {
        int r = 0;
        size_t n_entries=0;
        Hashmap *h = NULL;
        HashN *hh;
        const void *data;
        size_t length;
        const char *eq;
        Iterator i;
        Iterator i2;
        size_t nn;
        unsigned u;
        unsigned n_columns;
        StringKey sk;
        StringKey *psk;
        StringKey *psk2;
        size_t max_field_len = 1;
        int num_field_width;
        const char *csz;
        char *sz;
        char *sz1;
        char *sz2;
        const char *color_on = "", *color_off = "";
        double pct;

        r = sd_journal_set_data_threshold(j, 0);
        if (r < 0) { return log_error_errno(r, "Failed to unset data size threshold: %m"); }

        /* hash for field names */
        h = hashmap_new(&string_key_hash_ops);
        if (!h) { return log_oom(); }

        if (!!field) {
                /* We are only looking at ONE field name */

                /* To keep printing simple, behave like
                   when we are looking for all field names */

                hh = malloc(sizeof(HashN));
                if (!hh) { return log_oom(); }
                psk = malloc(sizeof(StringKey));
                psk->sz = strdup(field);
                psk->len = strlen(field);
                max_field_len = MAX(max_field_len, psk->len);
                r = hashmap_put(h, psk, hh);
                if (r < 0) { return log_error_errno(r, "Failed to hashmap_put: %m"); }
                hh->n = 0;
                hh->nv = 0;
                hh->h = hashmap_new(&string_key_hash_ops);
                if (!hh->h) { return log_oom(); }
                SD_JOURNAL_FOREACH(j) {
                        n_entries++;

                        r = sd_journal_get_data(j, field, &data, &length);
                        if (r < 0) { continue; }
                        eq = memchr(data, '=', length);
                        if (!eq) { continue; }

                        hh->n++;

                        sk.len = length - (eq - (const char*) data ) - 1;
                        sk.sz = (char*) eq+1;
                        r = put_journal_value(hh, sk);
                        if (r < 0) { return log_error_errno(r, "Failed to put_journal_value: %m"); }
                }
        } else {
                /* We want ALL field names */

                SD_JOURNAL_FOREACH(j) {
                        n_entries++;
                        JOURNAL_FOREACH_DATA_RETVAL(j, data, length, r) {

                                eq = memchr(data, '=', length);
                                if (!eq) { continue; }

                                sk.len = eq - (const char*) data;
                                sk.sz = (char*) data;
                                hh = hashmap_get(h, &sk);

                                if (hh == 0) {
                                        /* The field name was NOT found, so add it */

                                        max_field_len = MAX(max_field_len, sk.len);
                                        hh = malloc(sizeof(HashN));
                                        if (!hh) { return log_oom(); }

                                        psk = malloc(sizeof(StringKey));
                                        if (!psk) { return log_oom(); }
                                        psk->len = sk.len;
                                        psk->sz = (char*) strndup(data, eq - (const char*) data);
                                        if (!(psk->sz)) { return log_oom(); }

                                        r = hashmap_put(h, psk, hh);
                                        if (r < 0) { return log_error_errno(r, "Failed to hashmap_put: %m"); }

                                        hh->n = 1;
                                        hh->nv = 0;
                                        hh->h = hashmap_new(&string_key_hash_ops);
                                        if (!hh->h) { return log_oom(); }

                                } else {
                                        /* The field name WAS found, so update the entry */
                                        hh->n++;
                                        r = hashmap_update(h, &sk, hh);
                                        if (r < 0) { return log_error_errno(r, "Failed to hashmap_update: %m"); }
                                }

                                /* We now have a hash entry;
                                   either just created, or an updated one */

                                sk.len = length - (eq - (const char*) data ) - 1;
                                sk.sz = (char*) eq+1;

                                r = put_journal_value(hh, sk);
                                if (r < 0) { return log_error_errno(r, "Failed to put_journal_value: %m"); }
                        }
                        if (r < 0)
                                return log_error_errno(r, "Failed to get journal fields: %m");

                }
        }

        /* PREPARE FOR PRINTING */

        /* number of characters needed to print entry count */
        num_field_width = (int)log10(n_entries-1)+1;

        n_columns = on_tty() ? columns() : DEFAULT_COLUMNS;

        /* number of characters used for "boilerplate" in the printf below */
        u = 1 + 1 + num_field_width + 1 + 6+1 + 1 + num_field_width + 1 + (int)max_field_len + 1;

        /* We want at least MIN_COLUMNS for the value.
           If we do not have so many columns in one line, stretch to the end of next line(s) */
        if (u+MIN_COLUMNS>=n_columns) {
                n_columns = n_columns * (( (u+MIN_COLUMNS) + n_columns - 1) / n_columns);

        }

        n_columns = n_columns-u;

        if ( (n>1 || (!!field) ) && on_tty()) {
                color_on = ANSI_HIGHLIGHT;
                color_off = ANSI_NORMAL;
        }

        /* PRINT */

        HASHMAP_FOREACH_KEY(hh, psk, h, i) {
                        pct = (100.00*hh->n) / n_entries;
                        csz = ( (n<2) || (hh->nv<=MAX_VALUES) ) ? "" : "(Too many values)";
                        printf("F %s%*lu %6.2lf%% %s%*lu%s %*s %s%s\n", color_on, num_field_width, hh->n, pct, color_off, num_field_width, hh->nv, color_on, -(int)max_field_len, psk->sz, csz, color_off);

                if ( (!!field) || ( (n>1) && (hh->nv<=MAX_VALUES) ) ) {
                        HASHMAP_FOREACH_KEY(nn, psk2, hh->h, i2) {
                                pct = (100.00*nn) / hh->n;
                                sz = psk2->sz;
                                sz1 = NULL; /* To avoid free() later */
                                sz2 = NULL; /* To avoid free() later */

                                if (!utf8_is_printable(psk2->sz, psk2->len)) {
                                        char bytes[FORMAT_BYTES_MAX];
                                        char blob[MIN_COLUMNS];
                                        snprintf(blob, MIN_COLUMNS, "[%s blob data]", format_bytes(bytes, sizeof(bytes), psk2->len));
                                        sz = blob;
                                } else {
                                        sz1 = utf8_escape_non_printable_newline(sz, false);
                                        sz2 = ellipsize(sz1, n_columns, 100);
                                        sz=sz2;
                                }

                                printf("V %*lu %6.2lf%% %*s %*s %s\n", num_field_width, nn, pct, num_field_width, ":", -(int)max_field_len, psk->sz, sz);

                                if (!!sz1) { free(sz1); }
                                if (!!sz2) { free(sz2); }
                        }
                }

        }

        HASHMAP_FOREACH_KEY(hh, psk, h, i) {
                HASHMAP_FOREACH_KEY(nn, psk2, hh->h, i2) {
                        hashmap_remove(hh->h, psk2);
                        free(psk2->sz);
                        free(psk2);
                }
                hashmap_free(hh->h);
                hashmap_remove(h, psk);
                free(psk->sz);
                free(psk);
                free(hh);
        }

        hashmap_free(h);

        return r;
}
