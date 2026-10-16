/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-id128.h"

#include "journal-file.h"

#define MODEL_BOOT_A SD_ID128_MAKE(a1,a2,a3,a4,a5,a6,a7,a8,a9,aa,ab,ac,ad,ae,af,a0)
#define MODEL_BOOT_B SD_ID128_MAKE(b1,b2,b3,b4,b5,b6,b7,b8,b9,ba,bb,bc,bd,be,bf,b0)

/* Where the timestamps of the entries of model_append_generated() start */
#define MODEL_REALTIME_BASE ((usec_t) 1000000)

typedef struct Model {
        /* Expected contents of a file */
        char ***entries;
        usec_t *realtime;
        usec_t *monotonic;
        size_t n_entries;
} Model;

void model_done(Model *m);

/* Returns false if the test has to be skipped */
bool journal_test_setup(char **ret_directory);
JournalFile* journal_test_open(MMapCache *m, const char *name, int flags, uint64_t max_size);

void model_append(JournalFile *f, Model *model, usec_t realtime, usec_t monotonic, sd_id128_t boot_id, char **fields);
void model_append_generated(JournalFile *f, Model *model, uint64_t i);

void model_assert_entry(JournalFile *f, Object *o, uint64_t offset, const Model *model, size_t i);
void model_assert_file(JournalFile *f, const Model *model);
