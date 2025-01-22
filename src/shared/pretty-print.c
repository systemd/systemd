/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <sys/utsname.h>

#include "alloc-util.h"
#include "color-util.h"
#include "conf-files.h"
#include "constants.h"
#include "env-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "pager.h"
#include "path-util.h"
#include "pretty-print.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "utf8.h"

void draw_cylon(char buffer[], size_t buflen, unsigned width, unsigned pos) {
        char *p = buffer;

        assert(buflen >= CYLON_BUFFER_EXTRA + width + 1);
        assert(pos <= width+1); /* 0 or width+1 mean that the center light is behind the corner */

        if (pos > 1) {
                if (pos > 2)
                        p = mempset(p, ' ', pos-2);
                if (log_get_show_color())
                        p = stpcpy(p, ANSI_RED);
                *p++ = '*';
        }

        if (pos > 0 && pos <= width) {
                if (log_get_show_color())
                        p = stpcpy(p, ANSI_HIGHLIGHT_RED);
                *p++ = '*';
        }

        if (log_get_show_color())
                p = stpcpy(p, ANSI_NORMAL);

        if (pos < width) {
                if (log_get_show_color())
                        p = stpcpy(p, ANSI_RED);
                *p++ = '*';
                if (pos < width-1)
                        p = mempset(p, ' ', width-1-pos);
                if (log_get_show_color())
                        p = stpcpy(p, ANSI_NORMAL);
        }

        *p = '\0';
}

bool urlify_enabled(void) {
#if ENABLE_URLIFY
        static int cached_urlify_enabled = -1;

        if (cached_urlify_enabled < 0) {
                int val;

                val = getenv_bool("SYSTEMD_URLIFY");
                if (val >= 0)
                        cached_urlify_enabled = val;
                else
                        cached_urlify_enabled = colors_enabled();
        }

        return cached_urlify_enabled;
#else
        return 0;
#endif
}

static bool url_suitable_for_osc8(const char *url) {
        assert(url);

        /* Not all URLs are safe for inclusion in OSC 8 due to charset and length restrictions. Let's detect
         * which ones those are */

        /* If the URL is longer than 2K let's not try to do OSC 8. As per recommendation in
         * https://gist.github.com/egmontkob/eb114294efbcd5adb1944c9f3cb5feda#length-limits */
        if (strlen(url) > 2000)
                return false;

        /* OSC sequences may only contain chars from the 32..126 range, as per ECMA-48 */
        for (const char *c = url; *c; c++)
                if (!osc_char_is_valid(*c))
                        return false;

        return true;
}

int terminal_urlify(const char *url, const char *text, char **ret) {
        char *n;

        assert(url);

        /* Takes a URL and a pretty string and formats it as clickable link for the terminal. See
         * https://gist.github.com/egmontkob/eb114294efbcd5adb1944c9f3cb5feda for details. */

        if (isempty(text))
                text = url;

        if (urlify_enabled() && url_suitable_for_osc8(url))
                n = strjoin(ANSI_OSC "8;;", url, ANSI_ST,
                            text,
                            ANSI_OSC "8;;" ANSI_ST);
        else
                n = strdup(text);
        if (!n)
                return -ENOMEM;

        *ret = n;
        return 0;
}

int file_url_from_path(const char *path, char **ret) {
        _cleanup_free_ char *absolute = NULL;
        struct utsname u;
        char *url = NULL;
        int r;

        if (uname(&u) < 0)
                return -errno;

        if (!path_is_absolute(path)) {
                r = path_make_absolute_cwd(path, &absolute);
                if (r < 0)
                        return r;

                path = absolute;
        }

        /* As suggested by https://gist.github.com/egmontkob/eb114294efbcd5adb1944c9f3cb5feda, let's include the local
         * hostname here. Note that we don't use gethostname_malloc() or gethostname_strict() since we are interested
         * in the raw string the kernel has set, whatever it may be, under the assumption that terminals are not overly
         * careful with validating the strings either. */

        url = strjoin("file://", u.nodename, path);
        if (!url)
                return -ENOMEM;

        *ret = url;
        return 0;
}

int terminal_urlify_path(const char *path, const char *text, char **ret) {
        _cleanup_free_ char *url = NULL;
        int r;

        assert(path);

        /* Much like terminal_urlify() above, but takes a file system path as input
         * and turns it into a proper file:// URL first. */

        if (isempty(path))
                return -EINVAL;

        if (isempty(text))
                text = path;

        if (!urlify_enabled())
                return strdup_to(ret, text);

        r = file_url_from_path(path, &url);
        if (r < 0)
                return r;

        return terminal_urlify(url, text, ret);
}

int terminal_urlify_man(const char *page, const char *section, char **ret) {
        const char *url, *text;

        url = strjoina("man:", page, "(", section, ")");
        text = strjoina(page, "(", section, ") man page");

        return terminal_urlify(url, text, ret);
}

static int cat_file(const char *filename, bool newline, CatFlags flags) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *urlified = NULL, *section = NULL, *old_section = NULL;
        int r;

        assert(filename);

        f = fopen(filename, "re");
        if (!f)
                return log_error_errno(errno, "Failed to open \"%s\": %m", filename);

        r = terminal_urlify_path(filename, NULL, &urlified);
        if (r < 0)
                return log_error_errno(r, "Failed to urlify path \"%s\": %m", filename);

        printf("%s%s# %s%s\n",
               newline ? "\n" : "",
               ansi_highlight_blue(),
               urlified,
               ansi_normal());
        fflush(stdout);

        for (bool continued = false;;) {
                _cleanup_free_ char *line = NULL;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return log_error_errno(r, "Failed to read \"%s\": %m", filename);
                if (r == 0)
                        break;

                const char *l = skip_leading_chars(line, WHITESPACE);

                /* comment */
                if (*l != '\0' && strchr(COMMENTS, *l)) {
                        if (!FLAGS_SET(flags, CAT_TLDR))
                                printf("%s%s%s\n", ansi_highlight_grey(), line, ansi_normal());
                        continue;
                }

                /* empty line */
                if (FLAGS_SET(flags, CAT_TLDR) && (isempty(l) || streq(l, "\\")))
                        continue;

                /* section */
                if (FLAGS_SET(flags, CAT_FORMAT_HAS_SECTIONS) && *l == '[' && !continued) {
                        if (FLAGS_SET(flags, CAT_TLDR))
                                /* On TLDR, let's not print it yet. */
                                free_and_replace(section, line);
                        else
                                printf("%s%s%s\n", ansi_highlight_cyan(), line, ansi_normal());
                        continue;
                }

                /* normal line */

                /* Before we print the line, print the last section header. */
                if (FLAGS_SET(flags, CAT_TLDR) && section) {
                        /* Do not print redundant section headers */
                        if (!streq_ptr(section, old_section))
                                printf("%s%s%s\n", ansi_highlight_cyan(), section, ansi_normal());

                        free_and_replace(old_section, section);
                }

                /* Check if the line ends with a backslash. */
                bool escaped = false;
                char *e;
                for (e = line; *e != '\0'; e++) {
                        if (escaped)
                                escaped = false;
                        else if (*e == '\\')
                                escaped = true;
                }

                /* Highlight the trailing backslash. */
                if (escaped) {
                        assert(e > line);
                        *(e-1) = '\0';

                        if (!strextend(&line, ansi_highlight_red(), "\\", ansi_normal()))
                                return log_oom();
                }

                /* Highlight the left side (directive) of a Foo=bar assignment */
                if (FLAGS_SET(flags, CAT_FORMAT_HAS_SECTIONS) && !continued) {
                        const char *p = strchr(line, '=');
                        if (p) {
                                _cleanup_free_ char *directive = NULL;

                                directive = strndup(line, p - line);
                                if (!directive)
                                        return log_oom();

                                printf("%s%s=%s%s\n", ansi_highlight_green(), directive, ansi_normal(), p + 1);
                                continued = escaped;
                                continue;
                        }
                }

                /* Otherwise, print the line as is. */
                printf("%s\n", line);
                continued = escaped;
        }

        return 0;
}

int cat_files(const char *file, char **dropins, CatFlags flags) {
        int r;

        if (file) {
                r = cat_file(file, /* newline= */ false, flags);
                if (r < 0)
                        return log_warning_errno(r, "Failed to cat %s: %m", file);
        }

        STRV_FOREACH(path, dropins) {
                r = cat_file(*path, /* newline= */ file || path != dropins, flags);
                if (r < 0)
                        return log_warning_errno(r, "Failed to cat %s: %m", *path);
        }

        return 0;
}

void print_separator(void) {

        /* Outputs a separator line that resolves to whitespace when copied from the terminal. We do that by outputting
         * one line filled with spaces with ANSI underline set, followed by a second (empty) line. */

        if (underline_enabled()) {
                size_t c = columns();

                flockfile(stdout);
                fputs_unlocked(ansi_grey_underline(), stdout);

                for (size_t i = 0; i < c; i++)
                        fputc_unlocked(' ', stdout);

                fputs_unlocked(ansi_normal(), stdout);
                fputs_unlocked("\n\n", stdout);
                funlockfile(stdout);
        } else
                fputs("\n\n", stdout);
}

static int guess_type(const char **name, char ***ret_prefixes, bool *ret_is_collection, const char **ret_extension) {
        /* Try to figure out if name is like tmpfiles.d/ or systemd/system-presets/,
         * i.e. a collection of directories without a main config file.
         * Incidentally, all those formats don't use sections. So we return a single
         * is_collection boolean, which also means that the format doesn't use sections.
         */

        _cleanup_free_ char *n = NULL;
        bool run = false, coll = false;
        const char *ext = ".conf";
        /* This is static so that the array doesn't get deallocated when we exit the function */
        static const char* const std_prefixes[] = { CONF_PATHS(""), NULL };
        static const char* const run_prefixes[] = { "/run/", NULL };

        if (path_equal(*name, "environment.d"))
                /* Special case: we need to include /etc/environment in the search path, even
                 * though the whole concept is called environment.d. */
                *name = "environment";

        n = strdup(*name);
        if (!n)
                return log_oom();

        delete_trailing_chars(n, "/");

        /* We assume systemd-style config files support the /usr-/run-/etc split and dropins. */

        if (endswith(n, ".d"))
                coll = true;

        if (path_equal(n, "udev/hwdb.d"))
                ext = ".hwdb";
        else if (path_equal(n, "udev/rules.d"))
                ext = ".rules";
        else if (path_equal(n, "kernel/install.d"))
                ext = ".install";
        else if (path_equal(n, "systemd/ntp-units.d")) {
                coll = true;
                ext = ".list";
        } else if (path_equal(n, "systemd/relabel-extra.d")) {
                coll = run = true;
                ext = ".relabel";
        } else if (PATH_IN_SET(n, "systemd/system-preset", "systemd/user-preset")) {
                coll = true;
                ext = ".preset";
        }

        *ret_prefixes = (char**) (run ? run_prefixes : std_prefixes);
        *ret_is_collection = coll;
        *ret_extension = ext;
        return 0;
}

int conf_files_cat(const char *root, const char *name, CatFlags flags) {
        _cleanup_strv_free_ char **dirs = NULL, **files = NULL;
        _cleanup_free_ char *path = NULL;
        char **prefixes = NULL; /* explicit initialization to appease gcc */
        bool is_collection;
        const char *extension;
        int r;

        r = guess_type(&name, &prefixes, &is_collection, &extension);
        if (r < 0)
                return r;
        assert(prefixes);
        assert(extension);

        STRV_FOREACH(prefix, prefixes) {
                assert(endswith(*prefix, "/"));
                r = strv_extendf(&dirs, "%s%s%s", *prefix, name,
                                 is_collection ? "" : ".d");
                if (r < 0)
                        return log_error_errno(r, "Failed to build directory list: %m");
        }

        if (DEBUG_LOGGING) {
                log_debug("Looking for configuration in:");
                if (!is_collection)
                        STRV_FOREACH(prefix, prefixes)
                                log_debug("   %s%s%s", strempty(root), *prefix, name);

                STRV_FOREACH(t, dirs)
                        log_debug("   %s%s/*%s", strempty(root), *t, extension);
        }

        /* First locate the main config file, if any */
        if (!is_collection) {
                STRV_FOREACH(prefix, prefixes) {
                        path = path_join(root, *prefix, name);
                        if (!path)
                                return log_oom();
                        if (access(path, F_OK) == 0)
                                break;
                        path = mfree(path);
                }

                if (!path)
                        printf("%s# Main configuration file %s not found%s\n",
                               ansi_highlight_magenta(),
                               name,
                               ansi_normal());
        }

        /* Then locate the drop-ins, if any */
        r = conf_files_list_strv(&files, extension, root, 0, (const char* const*) dirs);
        if (r < 0)
                return log_error_errno(r, "Failed to query file list: %m");

        /* Show */
        if (is_collection)
                flags |= CAT_FORMAT_HAS_SECTIONS;

        return cat_files(path, files, flags);
}

int terminal_tint_color(double hue, char **ret) {
        double red, green, blue;
        int r;

        assert(ret);

        r = get_default_background_color(&red, &green, &blue);
        if (r < 0)
                return log_debug_errno(r, "Unable to get terminal background color: %m");

        double s, v;
        rgb_to_hsv(red, green, blue, /* h= */ NULL, &s, &v);

        if (v > 50) /* If the background is bright, then pull down saturation */
                s = 25;
        else        /* otherwise pump it up */
                s = 75;

        v = MAX(20, v); /* Make sure we don't hide the color in black */

        uint8_t r8, g8, b8;
        hsv_to_rgb(hue, s, v, &r8, &g8, &b8);

        if (asprintf(ret, "48;2;%u;%u;%u", r8, g8, b8) < 0)
                return -ENOMEM;

        return 0;
}

bool shall_tint_background(void) {
        static int cache = -1;

        if (cache >= 0)
                return cache;

        cache = getenv_bool("SYSTEMD_TINT_BACKGROUND");
        if (cache == -ENXIO)
                return (cache = true);
        if (cache < 0)
                log_debug_errno(cache, "Failed to parse $SYSTEMD_TINT_BACKGROUND, leaving background tinting enabled: %m");

        return cache != 0;
}

void draw_progress_bar_unbuffered(const char *prefix, double percentage) {
        fputc('\r', stderr);
        if (prefix) {
                fputs(prefix, stderr);
                fputc(' ', stderr);
        }

        if (!terminal_is_dumb()) {
                /* Generate the Windows Terminal progress indication OSC sequence here. Most Linux terminals currently
                 * ignore this. But let's hope this changes one day. For details about this OSC sequence, see:
                 *
                 * https://conemu.github.io/en/AnsiEscapeCodes.html#ConEmu_specific_OSC
                 * https://github.com/microsoft/terminal/pull/8055
                 */
                fprintf(stderr, ANSI_OSC "9;4;1;%u" ANSI_ST, (unsigned) ceil(percentage));

                size_t cols = columns();
                size_t prefix_width = utf8_console_width(prefix) + 1 /* space */;
                size_t length = cols > prefix_width + 6 ? cols - prefix_width - 6 : 0;

                if (length > 5 && percentage >= 0.0 && percentage <= 100.0) {
                        size_t p = (size_t) (length * percentage / 100.0);
                        bool separator_done = false;

                        fputs(ansi_highlight_green(), stderr);

                        for (size_t i = 0; i < length; i++) {

                                if (i <= p) {
                                        if (get_color_mode() == COLOR_24BIT) {
                                                uint8_t r8, g8, b8;
                                                double z = i == 0 ? 0 : (((double) i / p) * 100);
                                                hsv_to_rgb(145 /* green */, z, 33 + z*2/3, &r8, &g8, &b8);
                                                fprintf(stderr, "\x1B[38;2;%u;%u;%um", r8, g8, b8);
                                        }

                                        fputs(special_glyph(SPECIAL_GLYPH_HORIZONTAL_FAT), stderr);
                                } else if (i+1 < length && !separator_done) {
                                        fputs(ansi_normal(), stderr);
                                        fputc(' ', stderr);
                                        separator_done = true;
                                        fputs(ansi_grey(), stderr);
                                } else
                                        fputs(special_glyph(SPECIAL_GLYPH_HORIZONTAL_DOTTED), stderr);
                        }

                        fputs(ansi_normal(), stderr);
                        fputc(' ', stderr);
                }
        }

        fprintf(stderr,
                "%s%3.0f%%%s",
                ansi_highlight(),
                percentage,
                ansi_normal());

        if (!terminal_is_dumb())
                fputs(ANSI_ERASE_TO_END_OF_LINE, stderr);

        fputc('\r', stderr);
}

void clear_progress_bar_unbuffered(const char *prefix) {
        fputc('\r', stderr);

        if (terminal_is_dumb())
                fputs(strrepa(" ",
                              prefix ? utf8_console_width(prefix) + 5 : /* %3.0f%% (4 chars) + space */
                              LESS_BY(columns(), 1U)),
                      stderr);
        else
                /* Undo Windows Terminal progress indication again. */
                fputs(ANSI_OSC "9;4;0;" ANSI_ST
                      ANSI_ERASE_TO_END_OF_LINE, stderr);

        fputc('\r', stderr);
}

void draw_progress_bar(const char *prefix, double percentage) {
        /* We are going output a bunch of small strings that shall appear as a single line to STDERR which is
         * unbuffered by default. Let's temporarily turn on full buffering, so that this is passed to the tty
         * as a single buffer, to make things more efficient. */
        WITH_BUFFERED_STDERR;
        draw_progress_bar_unbuffered(prefix, percentage);
}

int draw_progress_barf(double percentage, const char *prefixf, ...) {
        _cleanup_free_ char *s = NULL;
        va_list ap;
        int r;

        va_start(ap, prefixf);
        r = vasprintf(&s, prefixf, ap);
        va_end(ap);

        if (r < 0)
                return -ENOMEM;

        draw_progress_bar(s, percentage);
        return 0;
}

void clear_progress_bar(const char *prefix) {
        WITH_BUFFERED_STDERR;
        clear_progress_bar_unbuffered(prefix);
}
