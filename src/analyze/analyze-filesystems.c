/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "analyze.h"
#include "analyze-filesystems.h"
#include "fileio.h"
#include "filesystems.h"
#include "set.h"
#include "strv.h"
#include "terminal-util.h"

static int load_available_kernel_filesystems(Set **ret) {
        _cleanup_set_free_ Set *filesystems = NULL;
        _cleanup_free_ char *t = NULL;
        int r;

        assert(ret);

        /* Let's read the available filesystems */

        r = read_virtual_file("/proc/filesystems", SIZE_MAX, &t, NULL);
        if (r < 0)
                return r;

        for (int i = 0;;) {
                _cleanup_free_ char *line = NULL;
                const char *p;

                r = string_extract_line(t, i++, &line);
                if (r < 0)
                        return log_oom();
                if (r == 0)
                        break;

                if (!line)
                        line = t;

                p = strchr(line, '\t');
                if (!p)
                        continue;

                p += strspn(p, WHITESPACE);

                r = set_put_strdup(&filesystems, p);
                if (r < 0)
                        return log_error_errno(r, "Failed to add filesystem to list: %m");
        }

        *ret = TAKE_PTR(filesystems);
        return 0;
}

static void filesystem_set_remove(Set *s, const FilesystemSet *set) {
        const char *filesystem;

        NULSTR_FOREACH(filesystem, set->value) {
                if (filesystem[0] == '@')
                        continue;

                free(set_remove(s, filesystem));
        }
}

static void dump_filesystem_set(const FilesystemSet *set) {
        const char *filesystem;
        int r;

        if (!set)
                return;

        printf("%s%s%s\n"
               "    # %s\n",
               ansi_highlight(),
               set->name,
               ansi_normal(),
               set->help);

        NULSTR_FOREACH(filesystem, set->value) {
                const statfs_f_type_t *magic;

                if (filesystem[0] == '@') {
                        printf("    %s%s%s\n", ansi_underline(), filesystem, ansi_normal());
                        continue;
                }

                r = fs_type_from_string(filesystem, &magic);
                assert_se(r >= 0);

                printf("    %s", filesystem);

                for (size_t i = 0; magic[i] != 0; i++) {
                        const char *primary;
                        if (i == 0)
                                printf(" %s(magic: ", ansi_grey());
                        else
                                printf(", ");

                        printf("0x%llx", (unsigned long long) magic[i]);

                        primary = fs_type_to_string(magic[i]);
                        if (primary && !streq(primary, filesystem))
                                printf("[%s]", primary);

                        if (magic[i+1] == 0)
                                printf(")%s", ansi_normal());
                }

                printf("\n");
        }
}

int verb_filesystems(int argc, char *argv[], void *userdata) {
        bool first = true;

#if ! HAVE_LIBBPF
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Not compiled with libbpf support, sorry.");
#endif

        pager_open(arg_pager_flags);

        if (strv_isempty(strv_skip(argv, 1))) {
                _cleanup_set_free_ Set *kernel = NULL, *known = NULL;
                const char *fs;
                int k;

                NULSTR_FOREACH(fs, filesystem_sets[FILESYSTEM_SET_KNOWN].value)
                        if (set_put_strdup(&known, fs) < 0)
                                return log_oom();

                k = load_available_kernel_filesystems(&kernel);

                for (FilesystemGroups i = 0; i < _FILESYSTEM_SET_MAX; i++) {
                        const FilesystemSet *set = filesystem_sets + i;
                        if (!first)
                                puts("");

                        dump_filesystem_set(set);
                        filesystem_set_remove(kernel, set);
                        if (i != FILESYSTEM_SET_KNOWN)
                                filesystem_set_remove(known, set);
                        first = false;
                }

                if (arg_quiet)  /* Let's not show the extra stuff in quiet mode */
                        return 0;

                if (!set_isempty(known)) {
                        _cleanup_free_ char **l = NULL;

                        printf("\n"
                               "# %sUngrouped filesystems%s (known but not included in any of the groups except @known):\n",
                               ansi_highlight(), ansi_normal());

                        l = set_get_strv(known);
                        if (!l)
                                return log_oom();

                        strv_sort(l);

                        STRV_FOREACH(filesystem, l) {
                                const statfs_f_type_t *magic;
                                bool is_primary = false;

                                assert_se(fs_type_from_string(*filesystem, &magic) >= 0);

                                for (size_t i = 0; magic[i] != 0; i++) {
                                        const char *primary;

                                        primary = fs_type_to_string(magic[i]);
                                        assert(primary);

                                        if (streq(primary, *filesystem))
                                                is_primary = true;
                                }

                                if (!is_primary) {
                                        log_debug("Skipping ungrouped file system '%s', because it's an alias for another one.", *filesystem);
                                        continue;
                                }

                                printf("#   %s\n", *filesystem);
                        }
                }

                if (k < 0) {
                        fputc('\n', stdout);
                        fflush(stdout);
                        log_notice_errno(k, "# Not showing unlisted filesystems, couldn't retrieve kernel filesystem list: %m");
                } else if (!set_isempty(kernel)) {
                        _cleanup_free_ char **l = NULL;

                        printf("\n"
                               "# %sUnlisted filesystems%s (available to the local kernel, but not included in any of the groups listed above):\n",
                               ansi_highlight(), ansi_normal());

                        l = set_get_strv(kernel);
                        if (!l)
                                return log_oom();

                        strv_sort(l);

                        STRV_FOREACH(filesystem, l)
                                printf("#   %s\n", *filesystem);
                }
        } else
                STRV_FOREACH(name, strv_skip(argv, 1)) {
                        const FilesystemSet *set;

                        if (!first)
                                puts("");

                        set = filesystem_set_find(*name);
                        if (!set) {
                                /* make sure the error appears below normal output */
                                fflush(stdout);

                                return log_error_errno(SYNTHETIC_ERRNO(ENOENT),
                                                       "Filesystem set \"%s\" not found.", *name);
                        }

                        dump_filesystem_set(set);
                        first = false;
                }

        return EXIT_SUCCESS;
}
