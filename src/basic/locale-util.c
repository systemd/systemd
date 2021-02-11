/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <langinfo.h>
#include <libintl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "def.h"
#include "dirent-util.h"
#include "env-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "locale-util.h"
#include "path-util.h"
#include "set.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "utf8.h"

static char *normalize_locale(const char *name) {
        const char *e;

        /* Locale names are weird: glibc has some magic rules when looking for the charset name on disk: it
         * lowercases everything, and removes most special chars. This means the official .UTF-8 suffix
         * becomes .utf8 when looking things up on disk. When enumerating locales, let's do the reverse
         * operation, and go back to ".UTF-8" which appears to be the more commonly accepted name. We only do
         * that for UTF-8 however, since it's kinda the only charset that matters. */

        e = endswith(name, ".utf8");
        if (e) {
                _cleanup_free_ char *prefix = NULL;

                prefix = strndup(name, e - name);
                if (!prefix)
                        return NULL;

                return strjoin(prefix, ".UTF-8");
        }

        e = strstr(name, ".utf8@");
        if (e) {
                _cleanup_free_ char *prefix = NULL;

                prefix = strndup(name, e - name);
                if (!prefix)
                        return NULL;

                return strjoin(prefix, ".UTF-8@", e + 6);
        }

        return strdup(name);
}

static int add_locales_from_archive(Set *locales) {
        /* Stolen from glibc... */

        struct locarhead {
                uint32_t magic;
                /* Serial number.  */
                uint32_t serial;
                /* Name hash table.  */
                uint32_t namehash_offset;
                uint32_t namehash_used;
                uint32_t namehash_size;
                /* String table.  */
                uint32_t string_offset;
                uint32_t string_used;
                uint32_t string_size;
                /* Table with locale records.  */
                uint32_t locrectab_offset;
                uint32_t locrectab_used;
                uint32_t locrectab_size;
                /* MD5 sum hash table.  */
                uint32_t sumhash_offset;
                uint32_t sumhash_used;
                uint32_t sumhash_size;
        };

        struct namehashent {
                /* Hash value of the name.  */
                uint32_t hashval;
                /* Offset of the name in the string table.  */
                uint32_t name_offset;
                /* Offset of the locale record.  */
                uint32_t locrec_offset;
        };

        const struct locarhead *h;
        const struct namehashent *e;
        const void *p = MAP_FAILED;
        _cleanup_close_ int fd = -1;
        size_t sz = 0;
        struct stat st;
        int r;

        fd = open("/usr/lib/locale/locale-archive", O_RDONLY|O_NOCTTY|O_CLOEXEC);
        if (fd < 0)
                return errno == ENOENT ? 0 : -errno;

        if (fstat(fd, &st) < 0)
                return -errno;

        if (!S_ISREG(st.st_mode))
                return -EBADMSG;

        if (st.st_size < (off_t) sizeof(struct locarhead))
                return -EBADMSG;

        p = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
        if (p == MAP_FAILED)
                return -errno;

        h = (const struct locarhead *) p;
        if (h->magic != 0xde020109 ||
            h->namehash_offset + h->namehash_size > st.st_size ||
            h->string_offset + h->string_size > st.st_size ||
            h->locrectab_offset + h->locrectab_size > st.st_size ||
            h->sumhash_offset + h->sumhash_size > st.st_size) {
                r = -EBADMSG;
                goto finish;
        }

        e = (const struct namehashent*) ((const uint8_t*) p + h->namehash_offset);
        for (size_t i = 0; i < h->namehash_size; i++) {
                char *z;

                if (e[i].locrec_offset == 0)
                        continue;

                if (!utf8_is_valid((char*) p + e[i].name_offset))
                        continue;

                z = normalize_locale((char*) p + e[i].name_offset);
                if (!z) {
                        r = -ENOMEM;
                        goto finish;
                }

                r = set_consume(locales, z);
                if (r < 0)
                        goto finish;
        }

        r = 0;

 finish:
        if (p != MAP_FAILED)
                munmap((void*) p, sz);

        return r;
}

static int add_locales_from_libdir (Set *locales) {
        _cleanup_closedir_ DIR *dir = NULL;
        struct dirent *entry;
        int r;

        dir = opendir("/usr/lib/locale");
        if (!dir)
                return errno == ENOENT ? 0 : -errno;

        FOREACH_DIRENT(entry, dir, return -errno) {
                char *z;

                dirent_ensure_type(dir, entry);

                if (entry->d_type != DT_DIR)
                        continue;

                z = normalize_locale(entry->d_name);
                if (!z)
                        return -ENOMEM;

                r = set_consume(locales, z);
                if (r < 0 && r != -EEXIST)
                        return r;
        }

        return 0;
}

int get_locales(char ***ret) {
        _cleanup_set_free_ Set *locales = NULL;
        _cleanup_strv_free_ char **l = NULL;
        int r;

        locales = set_new(&string_hash_ops);
        if (!locales)
                return -ENOMEM;

        r = add_locales_from_archive(locales);
        if (r < 0 && r != -ENOENT)
                return r;

        r = add_locales_from_libdir(locales);
        if (r < 0)
                return r;

        l = set_get_strv(locales);
        if (!l)
                return -ENOMEM;

        r = getenv_bool("SYSTEMD_LIST_NON_UTF8_LOCALES");
        if (r == -ENXIO || r == 0) {
                char **a, **b;

                /* Filter out non-UTF-8 locales, because it's 2019, by default */
                for (a = b = l; *a; a++) {

                        if (endswith(*a, "UTF-8") ||
                            strstr(*a, ".UTF-8@"))
                                *(b++) = *a;
                        else
                                free(*a);
                }

                *b = NULL;

        } else if (r < 0)
                log_debug_errno(r, "Failed to parse $SYSTEMD_LIST_NON_UTF8_LOCALES as boolean");

        strv_sort(l);

        *ret = TAKE_PTR(l);

        return 0;
}

bool locale_is_valid(const char *name) {

        if (isempty(name))
                return false;

        if (strlen(name) >= 128)
                return false;

        if (!utf8_is_valid(name))
                return false;

        if (!filename_is_valid(name))
                return false;

        if (!string_is_safe(name))
                return false;

        return true;
}

int locale_is_installed(const char *name) {
        if (!locale_is_valid(name))
                return false;

        if (STR_IN_SET(name, "C", "POSIX")) /* These ones are always OK */
                return true;

        _cleanup_(freelocalep) locale_t loc =
                newlocale(LC_ALL_MASK, name, 0);
        if (loc == (locale_t) 0)
                return errno == ENOMEM ? -ENOMEM : false;

        return true;
}

void init_gettext(void) {
        setlocale(LC_ALL, "");
        textdomain(GETTEXT_PACKAGE);
}

bool is_locale_utf8(void) {
        const char *set;
        static int cached_answer = -1;

        /* Note that we default to 'true' here, since today UTF8 is
         * pretty much supported everywhere. */

        if (cached_answer >= 0)
                goto out;

        if (!setlocale(LC_ALL, "")) {
                cached_answer = true;
                goto out;
        }

        set = nl_langinfo(CODESET);
        if (!set) {
                cached_answer = true;
                goto out;
        }

        if (streq(set, "UTF-8")) {
                cached_answer = true;
                goto out;
        }

        /* For LC_CTYPE=="C" return true, because CTYPE is effectively
         * unset and everything can do to UTF-8 nowadays. */
        set = setlocale(LC_CTYPE, NULL);
        if (!set) {
                cached_answer = true;
                goto out;
        }

        /* Check result, but ignore the result if C was set
         * explicitly. */
        cached_answer =
                STR_IN_SET(set, "C", "POSIX") &&
                !getenv("LC_ALL") &&
                !getenv("LC_CTYPE") &&
                !getenv("LANG");

out:
        return (bool) cached_answer;
}

bool emoji_enabled(void) {
        static int cached_emoji_enabled = -1;

        if (cached_emoji_enabled < 0) {
                int val;

                val = getenv_bool("SYSTEMD_EMOJI");
                if (val < 0)
                        cached_emoji_enabled =
                                is_locale_utf8() &&
                                !STRPTR_IN_SET(getenv("TERM"), "dumb", "linux");
                else
                        cached_emoji_enabled = val;
        }

        return cached_emoji_enabled;
}

const char *special_glyph(SpecialGlyph code) {

        /* A list of a number of interesting unicode glyphs we can use to decorate our output. It's probably wise to be
         * conservative here, and primarily stick to the glyphs defined in the eurlatgr font, so that display still
         * works reasonably well on the Linux console. For details see:
         *
         * http://git.altlinux.org/people/legion/packages/kbd.git?p=kbd.git;a=blob;f=data/consolefonts/README.eurlatgr
         */

        static const char* const draw_table[2][_SPECIAL_GLYPH_MAX] = {
                /* ASCII fallback */
                [false] = {
                        [SPECIAL_GLYPH_TREE_VERTICAL]           = "| ",
                        [SPECIAL_GLYPH_TREE_BRANCH]             = "|-",
                        [SPECIAL_GLYPH_TREE_RIGHT]              = "`-",
                        [SPECIAL_GLYPH_TREE_SPACE]              = "  ",
                        [SPECIAL_GLYPH_TRIANGULAR_BULLET]       = ">",
                        [SPECIAL_GLYPH_BLACK_CIRCLE]            = "*",
                        [SPECIAL_GLYPH_WHITE_CIRCLE]            = "*",
                        [SPECIAL_GLYPH_MULTIPLICATION_SIGN]     = "x",
                        [SPECIAL_GLYPH_CIRCLE_ARROW]            = "*",
                        [SPECIAL_GLYPH_BULLET]                  = "*",
                        [SPECIAL_GLYPH_MU]                      = "u",
                        [SPECIAL_GLYPH_CHECK_MARK]              = "+",
                        [SPECIAL_GLYPH_CROSS_MARK]              = "-",
                        [SPECIAL_GLYPH_LIGHT_SHADE]             = "-",
                        [SPECIAL_GLYPH_DARK_SHADE]              = "X",
                        [SPECIAL_GLYPH_SIGMA]                   = "S",
                        [SPECIAL_GLYPH_ARROW]                   = "->",
                        [SPECIAL_GLYPH_ELLIPSIS]                = "...",
                        [SPECIAL_GLYPH_EXTERNAL_LINK]           = "[LNK]",
                        [SPECIAL_GLYPH_ECSTATIC_SMILEY]         = ":-]",
                        [SPECIAL_GLYPH_HAPPY_SMILEY]            = ":-}",
                        [SPECIAL_GLYPH_SLIGHTLY_HAPPY_SMILEY]   = ":-)",
                        [SPECIAL_GLYPH_NEUTRAL_SMILEY]          = ":-|",
                        [SPECIAL_GLYPH_SLIGHTLY_UNHAPPY_SMILEY] = ":-(",
                        [SPECIAL_GLYPH_UNHAPPY_SMILEY]          = ":-{",
                        [SPECIAL_GLYPH_DEPRESSED_SMILEY]        = ":-[",
                        [SPECIAL_GLYPH_LOCK_AND_KEY]            = "o-,",
                        [SPECIAL_GLYPH_TOUCH]                   = "O=",    /* Yeah, not very convincing, can you do it better? */
                },

                /* UTF-8 */
                [true] = {
                        /* The following are multiple glyphs in both ASCII and in UNICODE */
                        [SPECIAL_GLYPH_TREE_VERTICAL]           = "\342\224\202 ",            /* │  */
                        [SPECIAL_GLYPH_TREE_BRANCH]             = "\342\224\234\342\224\200", /* ├─ */
                        [SPECIAL_GLYPH_TREE_RIGHT]              = "\342\224\224\342\224\200", /* └─ */
                        [SPECIAL_GLYPH_TREE_SPACE]              = "  ",                       /*    */

                        /* Single glyphs in both cases */
                        [SPECIAL_GLYPH_TRIANGULAR_BULLET]       = "\342\200\243",             /* ‣ */
                        [SPECIAL_GLYPH_BLACK_CIRCLE]            = "\342\227\217",             /* ● */
                        [SPECIAL_GLYPH_WHITE_CIRCLE]            = "\u25CB",                   /* ○ */
                        [SPECIAL_GLYPH_MULTIPLICATION_SIGN]     = "\u00D7",                   /* × */
                        [SPECIAL_GLYPH_CIRCLE_ARROW]            = "\u21BB",                   /* ↻ */
                        [SPECIAL_GLYPH_BULLET]                  = "\342\200\242",             /* • */
                        [SPECIAL_GLYPH_MU]                      = "\316\274",                 /* μ (actually called: GREEK SMALL LETTER MU) */
                        [SPECIAL_GLYPH_CHECK_MARK]              = "\342\234\223",             /* ✓ */
                        [SPECIAL_GLYPH_CROSS_MARK]              = "\342\234\227",             /* ✗ (actually called: BALLOT X) */
                        [SPECIAL_GLYPH_LIGHT_SHADE]             = "\342\226\221",             /* ░ */
                        [SPECIAL_GLYPH_DARK_SHADE]              = "\342\226\223",             /* ▒ */
                        [SPECIAL_GLYPH_SIGMA]                   = "\316\243",                 /* Σ */

                        /* Single glyph in Unicode, two in ASCII */
                        [SPECIAL_GLYPH_ARROW]                   = "\342\206\222",             /* → (actually called: RIGHTWARDS ARROW) */

                        /* Single glyph in Unicode, three in ASCII */
                        [SPECIAL_GLYPH_ELLIPSIS]                = "\342\200\246",             /* … (actually called: HORIZONTAL ELLIPSIS) */

                        /* Three glyphs in Unicode, five in ASCII */
                        [SPECIAL_GLYPH_EXTERNAL_LINK]           = "[\360\237\241\225]",       /* 🡕 (actually called: NORTH EAST SANS-SERIF ARROW, enclosed in []) */

                        /* These smileys are a single glyph in Unicode, and three in ASCII */
                        [SPECIAL_GLYPH_ECSTATIC_SMILEY]         = "\360\237\230\207",         /* 😇 (actually called: SMILING FACE WITH HALO) */
                        [SPECIAL_GLYPH_HAPPY_SMILEY]            = "\360\237\230\200",         /* 😀 (actually called: GRINNING FACE) */
                        [SPECIAL_GLYPH_SLIGHTLY_HAPPY_SMILEY]   = "\360\237\231\202",         /* 🙂 (actually called: SLIGHTLY SMILING FACE) */
                        [SPECIAL_GLYPH_NEUTRAL_SMILEY]          = "\360\237\230\220",         /* 😐 (actually called: NEUTRAL FACE) */
                        [SPECIAL_GLYPH_SLIGHTLY_UNHAPPY_SMILEY] = "\360\237\231\201",         /* 🙁 (actually called: SLIGHTLY FROWNING FACE) */
                        [SPECIAL_GLYPH_UNHAPPY_SMILEY]          = "\360\237\230\250",         /* 😨 (actually called: FEARFUL FACE) */
                        [SPECIAL_GLYPH_DEPRESSED_SMILEY]        = "\360\237\244\242",         /* 🤢 (actually called: NAUSEATED FACE) */

                        /* This emoji is a single character cell glyph in Unicode, and three in ASCII */
                        [SPECIAL_GLYPH_LOCK_AND_KEY]            = "\360\237\224\220",         /* 🔐 (actually called: CLOSED LOCK WITH KEY) */

                        /* This emoji is a single character cell glyph in Unicode, and two in ASCII */
                        [SPECIAL_GLYPH_TOUCH]                   = "\360\237\221\206",         /* 👆 (actually called: BACKHAND INDEX POINTING UP */
                },
        };

        assert(code < _SPECIAL_GLYPH_MAX);

        return draw_table[code >= _SPECIAL_GLYPH_FIRST_EMOJI ? emoji_enabled() : is_locale_utf8()][code];
}

void locale_variables_free(char *l[_VARIABLE_LC_MAX]) {
        if (!l)
                return;

        for (LocaleVariable i = 0; i < _VARIABLE_LC_MAX; i++)
                l[i] = mfree(l[i]);
}

static const char * const locale_variable_table[_VARIABLE_LC_MAX] = {
        [VARIABLE_LANG] = "LANG",
        [VARIABLE_LANGUAGE] = "LANGUAGE",
        [VARIABLE_LC_CTYPE] = "LC_CTYPE",
        [VARIABLE_LC_NUMERIC] = "LC_NUMERIC",
        [VARIABLE_LC_TIME] = "LC_TIME",
        [VARIABLE_LC_COLLATE] = "LC_COLLATE",
        [VARIABLE_LC_MONETARY] = "LC_MONETARY",
        [VARIABLE_LC_MESSAGES] = "LC_MESSAGES",
        [VARIABLE_LC_PAPER] = "LC_PAPER",
        [VARIABLE_LC_NAME] = "LC_NAME",
        [VARIABLE_LC_ADDRESS] = "LC_ADDRESS",
        [VARIABLE_LC_TELEPHONE] = "LC_TELEPHONE",
        [VARIABLE_LC_MEASUREMENT] = "LC_MEASUREMENT",
        [VARIABLE_LC_IDENTIFICATION] = "LC_IDENTIFICATION"
};

DEFINE_STRING_TABLE_LOOKUP(locale_variable, LocaleVariable);
