/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

/* Limits the use of ANSI colors to a subset. */
typedef enum ColorMode {
        COLOR_OFF,   /* No colors, monochrome output. */
        COLOR_16,    /* Only the base 16 colors. */
        COLOR_256,   /* Only 256 colors. */
        COLOR_24BIT, /* For truecolor or 24bit color support, no restriction. */
        _COLOR_MODE_MAX,
        _COLOR_MODE_INVALID = -EINVAL,
} ColorMode;

const char* color_mode_to_string(ColorMode m) _const_;
ColorMode color_mode_from_string(const char *s) _pure_;

ColorMode get_color_mode(void);
static inline bool colors_enabled(void) {
        /* Returns true if colors are considered supported on our stdout. */
        return get_color_mode() != COLOR_OFF;
}

ColorMode parse_systemd_colors(void);

bool underline_enabled(void);

void reset_ansi_feature_caches(void);

/* Regular colors */
#define ANSI_BLACK   "\x1B[0;30m" /* Some type of grey usually. */
#define ANSI_RED     "\x1B[0;31m"
#define ANSI_GREEN   "\x1B[0;32m"
#define ANSI_YELLOW  "\x1B[0;33m"
#define ANSI_BLUE    "\x1B[0;34m"
#define ANSI_MAGENTA "\x1B[0;35m"
#define ANSI_CYAN    "\x1B[0;36m"
#define ANSI_WHITE   "\x1B[0;37m" /* This is actually rendered as light grey, legible even on a white
                                   * background. See ANSI_HIGHLIGHT_WHITE for real white. */

#define ANSI_BRIGHT_BLACK   "\x1B[0;90m"
#define ANSI_BRIGHT_RED     "\x1B[0;91m"
#define ANSI_BRIGHT_GREEN   "\x1B[0;92m"
#define ANSI_BRIGHT_YELLOW  "\x1B[0;93m"
#define ANSI_BRIGHT_BLUE    "\x1B[0;94m"
#define ANSI_BRIGHT_MAGENTA "\x1B[0;95m"
#define ANSI_BRIGHT_CYAN    "\x1B[0;96m"
#define ANSI_BRIGHT_WHITE   "\x1B[0;97m"

#define ANSI_GREY    "\x1B[0;38:5:245m"

/* Bold/highlighted */
#define ANSI_HIGHLIGHT_BLACK    "\x1B[0;1;30m"
#define ANSI_HIGHLIGHT_RED      "\x1B[0;1;31m"
#define ANSI_HIGHLIGHT_GREEN    "\x1B[0;1;32m"
#define _ANSI_HIGHLIGHT_YELLOW  "\x1B[0;1;33m" /* This yellow is currently not displayed well by some terminals */
#define ANSI_HIGHLIGHT_BLUE     "\x1B[0;1;34m"
#define ANSI_HIGHLIGHT_MAGENTA  "\x1B[0;1;35m"
#define ANSI_HIGHLIGHT_CYAN     "\x1B[0;1;36m"
#define ANSI_HIGHLIGHT_WHITE    "\x1B[0;1;37m"
#define ANSI_HIGHLIGHT_YELLOW4  "\x1B[0;1;38:5:100m"
#define ANSI_HIGHLIGHT_KHAKI3   "\x1B[0;1;38:5:185m"
#define ANSI_HIGHLIGHT_GREY     "\x1B[0;1;38:5:245m"

#define ANSI_HIGHLIGHT_YELLOW   ANSI_HIGHLIGHT_KHAKI3 /* Replacement yellow that is more legible */

/* Underlined */
#define ANSI_GREY_UNDERLINE              "\x1B[0;4;38:5:245m"
#define ANSI_BRIGHT_BLACK_UNDERLINE      "\x1B[0;4;90m"
#define ANSI_HIGHLIGHT_RED_UNDERLINE     "\x1B[0;1;4;31m"
#define ANSI_HIGHLIGHT_GREEN_UNDERLINE   "\x1B[0;1;4;32m"
#define ANSI_HIGHLIGHT_YELLOW_UNDERLINE  "\x1B[0;1;4;38:5:185m"
#define ANSI_HIGHLIGHT_BLUE_UNDERLINE    "\x1B[0;1;4;34m"
#define ANSI_HIGHLIGHT_MAGENTA_UNDERLINE "\x1B[0;1;4;35m"
#define ANSI_HIGHLIGHT_GREY_UNDERLINE    "\x1B[0;1;4;38:5:245m"

/* Other ANSI codes */
#define ANSI_UNDERLINE "\x1B[0;4m"
#define ANSI_ADD_UNDERLINE "\x1B[4m"
#define ANSI_ADD_UNDERLINE_GREY ANSI_ADD_UNDERLINE "\x1B[58:5:245m"
#define ANSI_HIGHLIGHT "\x1B[0;1;39m"
#define ANSI_HIGHLIGHT_UNDERLINE "\x1B[0;1;4m"

/* Fallback colors: 256 → 16 */
#define ANSI_HIGHLIGHT_GREY_FALLBACK             "\x1B[0;1;90m"
#define ANSI_HIGHLIGHT_GREY_FALLBACK_UNDERLINE   "\x1B[0;1;4;90m"
#define ANSI_HIGHLIGHT_YELLOW_FALLBACK           "\x1B[0;1;33m"
#define ANSI_HIGHLIGHT_YELLOW_FALLBACK_UNDERLINE "\x1B[0;1;4;33m"

/* Background colors */
#define ANSI_BACKGROUND_BLUE "\x1B[44m"

/* Reset/clear ANSI styles */
#define ANSI_NORMAL "\x1B[0m"

#define DEFINE_ANSI_FUNC(name, NAME)                            \
        static inline const char* ansi_##name(void) {           \
                return colors_enabled() ? ANSI_##NAME : "";     \
        }

#define DEFINE_ANSI_FUNC_256(name, NAME, FALLBACK)             \
        static inline const char* ansi_##name(void) {          \
                switch (get_color_mode()) {                    \
                        case COLOR_OFF: return "";             \
                        case COLOR_16: return ANSI_##FALLBACK; \
                        default : return ANSI_##NAME;          \
                }                                              \
        }

static inline const char* ansi_underline(void) {
        return underline_enabled() ? ANSI_UNDERLINE : "";
}

static inline const char* ansi_add_underline(void) {
        return underline_enabled() ? ANSI_ADD_UNDERLINE : "";
}

static inline const char* ansi_add_underline_grey(void) {
        return underline_enabled() ?
                (colors_enabled() ? ANSI_ADD_UNDERLINE_GREY : ANSI_ADD_UNDERLINE) : "";
}

#define DEFINE_ANSI_FUNC_UNDERLINE(name, NAME)                          \
        static inline const char* ansi_##name(void) {                   \
                return underline_enabled() ? ANSI_##NAME##_UNDERLINE :  \
                        colors_enabled() ? ANSI_##NAME : "";            \
        }

#define DEFINE_ANSI_FUNC_UNDERLINE_256(name, NAME, FALLBACK)                                                        \
        static inline const char* ansi_##name(void) {                                                               \
                switch (get_color_mode()) {                                                                         \
                        case COLOR_OFF: return "";                                                                  \
                        case COLOR_16: return underline_enabled() ? ANSI_##FALLBACK##_UNDERLINE : ANSI_##FALLBACK;  \
                        default : return underline_enabled() ? ANSI_##NAME##_UNDERLINE: ANSI_##NAME;                \
                }                                                                                                   \
        }

DEFINE_ANSI_FUNC(normal,            NORMAL);
DEFINE_ANSI_FUNC(highlight,         HIGHLIGHT);
DEFINE_ANSI_FUNC(black,             BLACK);
DEFINE_ANSI_FUNC(red,               RED);
DEFINE_ANSI_FUNC(green,             GREEN);
DEFINE_ANSI_FUNC(yellow,            YELLOW);
DEFINE_ANSI_FUNC(blue,              BLUE);
DEFINE_ANSI_FUNC(magenta,           MAGENTA);
DEFINE_ANSI_FUNC(cyan,              CYAN);
DEFINE_ANSI_FUNC(white,             WHITE);
DEFINE_ANSI_FUNC_256(grey,          GREY, BRIGHT_BLACK);

DEFINE_ANSI_FUNC(bright_black,      BRIGHT_BLACK);
DEFINE_ANSI_FUNC(bright_red,        BRIGHT_RED);
DEFINE_ANSI_FUNC(bright_green,      BRIGHT_GREEN);
DEFINE_ANSI_FUNC(bright_yellow,     BRIGHT_YELLOW);
DEFINE_ANSI_FUNC(bright_blue,       BRIGHT_BLUE);
DEFINE_ANSI_FUNC(bright_magenta,    BRIGHT_MAGENTA);
DEFINE_ANSI_FUNC(bright_cyan,       BRIGHT_CYAN);
DEFINE_ANSI_FUNC(bright_white,      BRIGHT_WHITE);

DEFINE_ANSI_FUNC(highlight_black,       HIGHLIGHT_BLACK);
DEFINE_ANSI_FUNC(highlight_red,         HIGHLIGHT_RED);
DEFINE_ANSI_FUNC(highlight_green,       HIGHLIGHT_GREEN);
DEFINE_ANSI_FUNC_256(highlight_yellow,  HIGHLIGHT_YELLOW, HIGHLIGHT_YELLOW_FALLBACK);
DEFINE_ANSI_FUNC_256(highlight_yellow4, HIGHLIGHT_YELLOW4, HIGHLIGHT_YELLOW_FALLBACK);
DEFINE_ANSI_FUNC(highlight_blue,        HIGHLIGHT_BLUE);
DEFINE_ANSI_FUNC(highlight_magenta,     HIGHLIGHT_MAGENTA);
DEFINE_ANSI_FUNC(highlight_cyan,        HIGHLIGHT_CYAN);
DEFINE_ANSI_FUNC_256(highlight_grey,    HIGHLIGHT_GREY, HIGHLIGHT_GREY_FALLBACK);
DEFINE_ANSI_FUNC(highlight_white,       HIGHLIGHT_WHITE);

static inline const char* _ansi_highlight_yellow(void) {
        return colors_enabled() ? _ANSI_HIGHLIGHT_YELLOW : "";
}

DEFINE_ANSI_FUNC_UNDERLINE(highlight_underline,             HIGHLIGHT);
DEFINE_ANSI_FUNC_UNDERLINE_256(grey_underline,              GREY, BRIGHT_BLACK);
DEFINE_ANSI_FUNC_UNDERLINE(highlight_red_underline,         HIGHLIGHT_RED);
DEFINE_ANSI_FUNC_UNDERLINE(highlight_green_underline,       HIGHLIGHT_GREEN);
DEFINE_ANSI_FUNC_UNDERLINE_256(highlight_yellow_underline,  HIGHLIGHT_YELLOW, HIGHLIGHT_YELLOW_FALLBACK);
DEFINE_ANSI_FUNC_UNDERLINE(highlight_blue_underline,        HIGHLIGHT_BLUE);
DEFINE_ANSI_FUNC_UNDERLINE(highlight_magenta_underline,     HIGHLIGHT_MAGENTA);
DEFINE_ANSI_FUNC_UNDERLINE_256(highlight_grey_underline,    HIGHLIGHT_GREY, HIGHLIGHT_GREY_FALLBACK);

static inline const char* ansi_highlight_green_red(bool b) {
        return b ? ansi_highlight_green() : ansi_highlight_red();
}
