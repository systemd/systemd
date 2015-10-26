/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include <langinfo.h>
#include <locale.h>
#include <sys/mman.h>

#include "dirent-util.h"
#include "fd-util.h"
#include "locale-util.h"
#include "path-util.h"
#include "set.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "utf8.h"
#include "util.h"

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
        unsigned i;
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
        for (i = 0; i < h->namehash_size; i++) {
                char *z;

                if (e[i].locrec_offset == 0)
                        continue;

                if (!utf8_is_valid((char*) p + e[i].name_offset))
                        continue;

                z = strdup((char*) p + e[i].name_offset);
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

                if (entry->d_type != DT_DIR)
                        continue;

                z = strdup(entry->d_name);
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

        strv_sort(l);

        *ret = l;
        l = NULL;

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

        /* For LC_CTYPE=="C" return true, because CTYPE is effectly
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


const char *draw_special_char(DrawSpecialChar ch) {

        static const char *draw_table[2][_DRAW_SPECIAL_CHAR_MAX] = {

                /* UTF-8 */ {
                        [DRAW_TREE_VERTICAL]      = "\342\224\202 ",            /* │  */
                        [DRAW_TREE_BRANCH]        = "\342\224\234\342\224\200", /* ├─ */
                        [DRAW_TREE_RIGHT]         = "\342\224\224\342\224\200", /* └─ */
                        [DRAW_TREE_SPACE]         = "  ",                       /*    */
                        [DRAW_TRIANGULAR_BULLET]  = "\342\200\243",             /* ‣ */
                        [DRAW_BLACK_CIRCLE]       = "\342\227\217",             /* ● */
                        [DRAW_ARROW]              = "\342\206\222",             /* → */
                        [DRAW_DASH]               = "\342\200\223",             /* – */
                },

                /* ASCII fallback */ {
                        [DRAW_TREE_VERTICAL]      = "| ",
                        [DRAW_TREE_BRANCH]        = "|-",
                        [DRAW_TREE_RIGHT]         = "`-",
                        [DRAW_TREE_SPACE]         = "  ",
                        [DRAW_TRIANGULAR_BULLET]  = ">",
                        [DRAW_BLACK_CIRCLE]       = "*",
                        [DRAW_ARROW]              = "->",
                        [DRAW_DASH]               = "-",
                }
        };

        return draw_table[!is_locale_utf8()][ch];
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
