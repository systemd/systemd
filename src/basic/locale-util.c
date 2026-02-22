/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <langinfo.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "dirent-util.h"
#include "env-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "locale-util.h"
#include "log.h"
#include "path-util.h"
#include "process-util.h"
#include "set.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "utf8.h"

static char* normalize_locale(const char *name) {
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

static const char* get_locale_dir(void) {
        return secure_getenv("SYSTEMD_LOCALE_DIRECTORY") ?:
#ifdef __GLIBC__
                "/usr/lib/locale/";
#else
                "/usr/share/i18n/locales/musl/";
#endif
}

#ifdef __GLIBC__
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

        int r;

        assert(locales);

        _cleanup_free_ char *locale_archive_file = path_join(get_locale_dir(), "locale-archive");
        if (!locale_archive_file)
                return -ENOMEM;

        _cleanup_close_ int fd = open(locale_archive_file, O_RDONLY|O_NOCTTY|O_CLOEXEC);
        if (fd < 0)
                return errno == ENOENT ? 0 : -errno;

        struct stat st;
        if (fstat(fd, &st) < 0)
                return -errno;

        if (!S_ISREG(st.st_mode))
                return -EBADMSG;

        if (st.st_size < (off_t) sizeof(struct locarhead))
                return -EBADMSG;

        if (file_offset_beyond_memory_size(st.st_size))
                return -EFBIG;

        void *p = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
        if (p == MAP_FAILED)
                return -errno;

        const struct namehashent *e;
        const struct locarhead *h = p;
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
                munmap(p, st.st_size);

        return r;
}

static int add_locales_from_libdir(Set *locales) {
        _cleanup_closedir_ DIR *dir = NULL;
        int r;

        assert(locales);

        dir = opendir(get_locale_dir());
        if (!dir)
                return errno == ENOENT ? 0 : -errno;

        FOREACH_DIRENT(de, dir, return -errno) {
                char *z;

                if (de->d_type != DT_DIR)
                        continue;

                z = normalize_locale(de->d_name);
                if (!z)
                        return -ENOMEM;

                r = set_consume(locales, z);
                if (r < 0)
                        return r;
        }

        return 0;
}

#else

static int add_locales_for_musl(Set *locales) {
        int r;

        assert(locales);

        _cleanup_closedir_ DIR *dir = opendir(get_locale_dir());
        if (!dir)
                return errno == ENOENT ? 0 : -errno;

        FOREACH_DIRENT(de, dir, return -errno) {
                if (de->d_type != DT_REG)
                        continue;

                char *z = normalize_locale(de->d_name);
                if (!z)
                        return -ENOMEM;

                r = set_consume(locales, z);
                if (r < 0)
                        return r;
        }

        return 0;
}
#endif

int get_locales(char ***ret) {
        _cleanup_set_free_ Set *locales = NULL;
        int r;

        locales = set_new(&string_hash_ops_free);
        if (!locales)
                return -ENOMEM;

#ifdef __GLIBC__
        r = add_locales_from_archive(locales);
        if (r < 0 && r != -ENOENT)
                return r;

        r = add_locales_from_libdir(locales);
        if (r < 0)
                return r;
#else
        r = add_locales_for_musl(locales);
        if (r < 0)
                return r;
#endif

        char *locale;
        SET_FOREACH(locale, locales) {
                r = locale_is_installed(locale);
                if (r < 0)
                        return r;
                if (r == 0)
                        free(set_remove(locales, locale));
        }

        _cleanup_strv_free_ char **l = set_to_strv(&locales);
        if (!l)
                return -ENOMEM;

        r = getenv_bool("SYSTEMD_LIST_NON_UTF8_LOCALES");
        if (r <= 0) {
                if (!IN_SET(r, -ENXIO, 0))
                        log_debug_errno(r, "Failed to parse $SYSTEMD_LIST_NON_UTF8_LOCALES as boolean, ignoring: %m");

                /* Filter out non-UTF-8 locales, because it's 2019, by default */
                char **b = l;
                STRV_FOREACH(a, l)
                        if (endswith(*a, "UTF-8") || strstr(*a, ".UTF-8@"))
                                *(b++) = *a;
                        else
                                free(*a);

                *b = NULL;
        }

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

        /* Locales look like: ll_CC.ENC@variant, where ll and CC are alphabetic, ENC is alphanumeric with
         * dashes, and variant seems to be alphabetic.
         * See: https://www.gnu.org/software/gettext/manual/html_node/Locale-Names.html */
        if (!in_charset(name, ALPHANUMERICAL "_.-@"))
                return false;

        return true;
}

int locale_is_installed(const char *name) {
        if (!locale_is_valid(name))
                return false;

        if (STR_IN_SET(name, "C", "POSIX")) /* These ones are always OK */
                return true;

#ifdef __GLIBC__
        _cleanup_(freelocalep) locale_t loc = newlocale(LC_ALL_MASK, name, (locale_t) 0);
        if (loc == (locale_t) 0)
                return errno == ENOMEM ? -ENOMEM : false;

        return true;
#else
        /* musl also has C.UTF-8 as builtin */
        if (streq(name, "C.UTF-8"))
                return true;

        /* musl's newlocale() always succeeds and provides a fake locale object even when the locale does
         * not exist. Hence, we need to explicitly check if the locale file exists. */
        _cleanup_free_ char *p = path_join(get_locale_dir(), name);
        if (!p)
                return -ENOMEM;

        return access(p, F_OK) >= 0;
#endif
}

static bool is_locale_utf8_impl(void) {
        const char *set;
        int r;

        /* Note that we default to 'true' here, since today UTF8 is pretty much supported everywhere. */

        r = secure_getenv_bool("SYSTEMD_UTF8");
        if (r >= 0)
                return r;
        if (r != -ENXIO)
                log_debug_errno(r, "Failed to parse $SYSTEMD_UTF8, ignoring: %m");

        /* This function may be called from libsystemd, and setlocale() is not thread safe. Assuming yes. */
        if (!is_main_thread())
                return true;

        if (!setlocale(LC_ALL, ""))
                return true;

        set = nl_langinfo(CODESET);
        if (!set || streq(set, "UTF-8"))
                return true;

        set = setlocale(LC_CTYPE, NULL);
        if (!set)
                return true;

        /* Unless LC_CTYPE is explicitly overridden, return true. Because here CTYPE is effectively unset
         * and everything can do to UTF-8 nowadays. */
        return STR_IN_SET(set, "C", "POSIX") &&
                !getenv("LC_ALL") &&
                !getenv("LC_CTYPE") &&
                !getenv("LANG");
}

bool is_locale_utf8(void) {
        static int cached = -1;

        if (cached < 0)
                cached = is_locale_utf8_impl();

        return cached;
}

void locale_variables_free(char *l[_VARIABLE_LC_MAX]) {
        free_many_charp(l, _VARIABLE_LC_MAX);
}

void locale_variables_simplify(char *l[_VARIABLE_LC_MAX]) {
        assert(l);

        for (LocaleVariable p = 0; p < _VARIABLE_LC_MAX; p++) {
                if (p == VARIABLE_LANG)
                        continue;
                if (isempty(l[p]) || streq_ptr(l[VARIABLE_LANG], l[p]))
                        l[p] = mfree(l[p]);
        }
}

static const char * const locale_variable_table[_VARIABLE_LC_MAX] = {
        [VARIABLE_LANG]              = "LANG",
        [VARIABLE_LANGUAGE]          = "LANGUAGE",
        [VARIABLE_LC_CTYPE]          = "LC_CTYPE",
        [VARIABLE_LC_NUMERIC]        = "LC_NUMERIC",
        [VARIABLE_LC_TIME]           = "LC_TIME",
        [VARIABLE_LC_COLLATE]        = "LC_COLLATE",
        [VARIABLE_LC_MONETARY]       = "LC_MONETARY",
        [VARIABLE_LC_MESSAGES]       = "LC_MESSAGES",
        [VARIABLE_LC_PAPER]          = "LC_PAPER",
        [VARIABLE_LC_NAME]           = "LC_NAME",
        [VARIABLE_LC_ADDRESS]        = "LC_ADDRESS",
        [VARIABLE_LC_TELEPHONE]      = "LC_TELEPHONE",
        [VARIABLE_LC_MEASUREMENT]    = "LC_MEASUREMENT",
        [VARIABLE_LC_IDENTIFICATION] = "LC_IDENTIFICATION"
};

DEFINE_STRING_TABLE_LOOKUP(locale_variable, LocaleVariable);
