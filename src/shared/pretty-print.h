/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "ansi-color.h"
#include "glyph-util.h"
#include "terminal-util.h"

#define CYLON_BUFFER_EXTRA (2*STRLEN(ANSI_RED) + STRLEN(ANSI_HIGHLIGHT_RED) + 2*STRLEN(ANSI_NORMAL))

void draw_cylon(char buffer[], size_t buflen, unsigned width, unsigned pos);

void print_separator(void);

int file_url_from_path(const char *path, char **ret);

bool urlify_enabled(void);

int terminal_urlify(const char *url, const char *text, char **ret);
int terminal_urlify_path(const char *path, const char *text, char **ret);
int terminal_urlify_man(const char *page, const char *section, char **ret);

typedef enum CatFlags {
        CAT_CONFIG_OFF          = 0,
        CAT_CONFIG_ON           = 1 << 0,
        CAT_FORMAT_HAS_SECTIONS = 1 << 1,  /* Sections are meaningful for this file format */
        CAT_TLDR                = 1 << 2,  /* Only print comments and relevant section headers */
} CatFlags;

int cat_files(const char *file, char **dropins, CatFlags flags);
int conf_files_cat(const char *root, const char *name, CatFlags flags);

#define RED_CROSS_MARK_MAX (STRLEN(ANSI_HIGHLIGHT_RED) + STRLEN("✗") + STRLEN(ANSI_NORMAL) + 1)
#define GREEN_CHECK_MARK_MAX (STRLEN(ANSI_HIGHLIGHT_GREEN) + STRLEN("✓") + STRLEN(ANSI_NORMAL) + 1)

static inline const char* red_cross_mark_internal(char buffer[static RED_CROSS_MARK_MAX]) {
        assert(buffer);
        assert_se(stpcpy(stpcpy(stpcpy(buffer, ansi_highlight_red()), special_glyph(SPECIAL_GLYPH_CROSS_MARK)), ansi_normal()) < buffer + RED_CROSS_MARK_MAX);
        return buffer;
}

static inline const char* green_check_mark_internal(char buffer[static GREEN_CHECK_MARK_MAX]) {
        assert(buffer);
        assert_se(stpcpy(stpcpy(stpcpy(buffer, ansi_highlight_green()), special_glyph(SPECIAL_GLYPH_CHECK_MARK)), ansi_normal()) < buffer + GREEN_CHECK_MARK_MAX);
        return buffer;
}

#define RED_CROSS_MARK() red_cross_mark_internal((char[RED_CROSS_MARK_MAX]) {})
#define GREEN_CHECK_MARK() green_check_mark_internal((char[GREEN_CHECK_MARK_MAX]) {})

#define COLOR_MARK_BOOL(b) ((b) ? GREEN_CHECK_MARK() : RED_CROSS_MARK())

int terminal_tint_color(double hue, char **ret);

bool shall_tint_background(void);

void draw_progress_bar(const char *prefix, double percentage);
int draw_progress_barf(double percentage, const char *prefixf, ...) _printf_(2, 3);
void clear_progress_bar(const char *prefix);
void draw_progress_bar_unbuffered(const char *prefix, double percentage);
void clear_progress_bar_unbuffered(const char *prefix);

static inline FILE* enable_buffering(FILE *f, char *buffer, size_t size) {
        assert(f);
        assert(buffer);
        assert(size > 0);

        if (setvbuf(f, buffer, _IOFBF, size) != 0)
                return NULL;

        return f;
}

static inline void fflush_and_disable_bufferingp(FILE **p) {
        assert(p);

        if (*p) {
                fflush(*p);
                setvbuf(*p, NULL, _IONBF, 0); /* Disable buffering again. */
        }
}

/* Even though the macro below is slightly generic, but it may not work most streams except for stderr,
 * as stdout is buffered and fopen() enables buffering by default. */
#define _WITH_BUFFERED_STREAM(f, size, p)                               \
        _unused_ _cleanup_(fflush_and_disable_bufferingp) FILE *p =     \
                enable_buffering(f, (char[size]) {}, size)

#define WITH_BUFFERED_STDERR                                            \
        _WITH_BUFFERED_STREAM(stderr, LONG_LINE_MAX, UNIQ_T(p, UNIQ))
