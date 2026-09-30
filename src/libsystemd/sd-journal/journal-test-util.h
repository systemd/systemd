/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-id128.h"

#include "journal-file.h"
#include "tests.h"

#define MODEL_BOOT_A SD_ID128_MAKE(a1,a2,a3,a4,a5,a6,a7,a8,a9,aa,ab,ac,ad,ae,af,a0)
#define MODEL_BOOT_B SD_ID128_MAKE(b1,b2,b3,b4,b5,b6,b7,b8,b9,ba,bb,bc,bd,be,bf,b0)

/* Where the timestamps of the entries of model_append_generated() start by default */
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
void journal_test_refresh(JournalFile *f);
bool journal_test_segmented(void);

void model_append(JournalFile *f, Model *model, usec_t realtime, usec_t monotonic, sd_id128_t boot_id, char **fields);
void model_append_generated_at(JournalFile *f, Model *model, uint64_t i, usec_t realtime_base);
static inline void model_append_generated(JournalFile *f, Model *model, uint64_t i) {
        model_append_generated_at(f, model, i, MODEL_REALTIME_BASE);
}

void model_assert_entry(JournalFile *f, Object *o, uint64_t offset, const Model *model, size_t i);
void model_assert_file(JournalFile *f, const Model *model);

int journal_test_main(int argc, char *argv[], int log_level, int (*intro)(void), const TestFunc *start, const TestFunc *end);

/* Runs all tests once with classic and once with segmented files */
#define DEFINE_JOURNAL_TEST_MAIN_WITH_INTRO(log_level, intro)                                             \
        int main(int argc, char *argv[]) {                                                                \
                return journal_test_main(argc, argv, log_level, intro,                                    \
                                         __start_SYSTEMD_TEST_TABLE, __stop_SYSTEMD_TEST_TABLE);         \
        }

#define DEFINE_JOURNAL_TEST_MAIN(log_level) DEFINE_JOURNAL_TEST_MAIN_WITH_INTRO(log_level, NULL)
