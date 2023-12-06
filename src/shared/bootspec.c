/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "bootspec-fundamental.h"
#include "bootspec.h"
#include "chase.h"
#include "conf-files.h"
#include "devnum-util.h"
#include "dirent-util.h"
#include "efi-loader.h"
#include "env-file.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "find-esp.h"
#include "path-util.h"
#include "pe-binary.h"
#include "pretty-print.h"
#include "recurse-dir.h"
#include "sort-util.h"
#include "stat-util.h"
#include "string-table.h"
#include "strv.h"
#include "terminal-util.h"
#include "unaligned.h"

static const char* const boot_entry_type_table[_BOOT_ENTRY_TYPE_MAX] = {
        [BOOT_ENTRY_CONF]        = "Boot Loader Specification Type #1 (.conf)",
        [BOOT_ENTRY_UNIFIED]     = "Boot Loader Specification Type #2 (.efi)",
        [BOOT_ENTRY_LOADER]      = "Reported by Boot Loader",
        [BOOT_ENTRY_LOADER_AUTO] = "Automatic",
};

DEFINE_STRING_TABLE_LOOKUP_TO_STRING(boot_entry_type, BootEntryType);

static const char* const boot_entry_type_json_table[_BOOT_ENTRY_TYPE_MAX] = {
        [BOOT_ENTRY_CONF]        = "type1",
        [BOOT_ENTRY_UNIFIED]     = "type2",
        [BOOT_ENTRY_LOADER]      = "loader",
        [BOOT_ENTRY_LOADER_AUTO] = "auto",
};

DEFINE_STRING_TABLE_LOOKUP_TO_STRING(boot_entry_type_json, BootEntryType);

static void boot_entry_free(BootEntry *entry) {
        assert(entry);

        free(entry->id);
        free(entry->id_old);
        free(entry->path);
        free(entry->root);
        free(entry->title);
        free(entry->show_title);
        free(entry->sort_key);
        free(entry->version);
        free(entry->machine_id);
        free(entry->architecture);
        strv_free(entry->options);
        free(entry->kernel);
        free(entry->efi);
        strv_free(entry->initrd);
        free(entry->device_tree);
        strv_free(entry->device_tree_overlay);
}

static int mangle_path(
                const char *fname,
                unsigned line,
                const char *field,
                const char *p,
                char **ret) {

        _cleanup_free_ char *c = NULL;

        assert(field);
        assert(p);
        assert(ret);

        /* Spec leaves open if prefixed with "/" or not, let's normalize that */
        if (path_is_absolute(p))
                c = strdup(p);
        else
                c = strjoin("/", p);
        if (!c)
                return -ENOMEM;

        /* We only reference files, never directories */
        if (endswith(c, "/")) {
                log_syntax(NULL, LOG_WARNING, fname, line, 0, "Path in field '%s' has trailing slash, ignoring: %s", field, c);
                *ret = NULL;
                return 0;
        }

        /* Remove duplicate "/" */
        path_simplify(c);

        /* No ".." or "." or so */
        if (!path_is_normalized(c)) {
                log_syntax(NULL, LOG_WARNING, fname, line, 0, "Path in field '%s' is not normalized, ignoring: %s", field, c);
                *ret = NULL;
                return 0;
        }

        *ret = TAKE_PTR(c);
        return 1;
}

static int parse_path_one(
                const char *fname,
                unsigned line,
                const char *field,
                char **s,
                const char *p) {

        _cleanup_free_ char *c = NULL;
        int r;

        assert(field);
        assert(s);
        assert(p);

        r = mangle_path(fname, line, field, p, &c);
        if (r <= 0)
                return r;

        return free_and_replace(*s, c);
}

static int parse_path_strv(
                const char *fname,
                unsigned line,
                const char *field,
                char ***s,
                const char *p) {

        char *c;
        int r;

        assert(field);
        assert(s);
        assert(p);

        r = mangle_path(fname, line, field, p, &c);
        if (r <= 0)
                return r;

        return strv_consume(s, c);
}

static int parse_path_many(
                const char *fname,
                unsigned line,
                const char *field,
                char ***s,
                const char *p) {

        _cleanup_strv_free_ char **l = NULL, **f = NULL;
        int r;

        l = strv_split(p, NULL);
        if (!l)
                return -ENOMEM;

        STRV_FOREACH(i, l) {
                char *c;

                r = mangle_path(fname, line, field, *i, &c);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                r = strv_consume(&f, c);
                if (r < 0)
                        return r;
        }

        return strv_extend_strv(s, f, /* filter_duplicates= */ false);
}

static int parse_tries(const char *fname, const char **p, unsigned *ret) {
        _cleanup_free_ char *d = NULL;
        unsigned tries;
        size_t n;
        int r;

        assert(fname);
        assert(p);
        assert(*p);
        assert(ret);

        n = strspn(*p, DIGITS);
        if (n == 0) {
                *ret = UINT_MAX;
                return 0;
        }

        d = strndup(*p, n);
        if (!d)
                return log_oom();

        r = safe_atou_full(d, 10, &tries);
        if (r >= 0 && tries > INT_MAX) /* sd-boot allows INT_MAX, let's use the same limit */
                r = -ERANGE;
        if (r < 0)
                return log_error_errno(r, "Failed to parse tries counter of filename '%s': %m", fname);

        *p = *p + n;
        *ret = tries;
        return 1;
}

int boot_filename_extract_tries(
                const char *fname,
                char **ret_stripped,
                unsigned *ret_tries_left,
                unsigned *ret_tries_done) {

        unsigned tries_left = UINT_MAX, tries_done = UINT_MAX;
        _cleanup_free_ char *stripped = NULL;
        const char *p, *suffix, *m;
        int r;

        assert(fname);
        assert(ret_stripped);
        assert(ret_tries_left);
        assert(ret_tries_done);

        /* Be liberal with suffix, only insist on a dot. After all we want to cover any capitalization here
         * (vfat is case insensitive after all), and at least .efi and .conf as suffix. */
        suffix = strrchr(fname, '.');
        if (!suffix)
                goto nothing;

        p = m = memrchr(fname, '+', suffix - fname);
        if (!p)
                goto nothing;
        p++;

        r = parse_tries(fname, &p, &tries_left);
        if (r < 0)
                return r;
        if (r == 0)
                goto nothing;

        if (*p == '-') {
                p++;

                r = parse_tries(fname, &p, &tries_done);
                if (r < 0)
                        return r;
                if (r == 0)
                        goto nothing;
        }

        if (p != suffix)
                goto nothing;

        stripped = strndup(fname, m - fname);
        if (!stripped)
                return log_oom();

        if (!strextend(&stripped, suffix))
                return log_oom();

        *ret_stripped = TAKE_PTR(stripped);
        *ret_tries_left = tries_left;
        *ret_tries_done = tries_done;

        return 0;

nothing:
        stripped = strdup(fname);
        if (!stripped)
                return log_oom();

        *ret_stripped = TAKE_PTR(stripped);
        *ret_tries_left = *ret_tries_done = UINT_MAX;
        return 0;
}

static int boot_entry_load_type1(
                FILE *f,
                const char *root,
                const char *dir,
                const char *fname,
                BootEntry *entry) {

        _cleanup_(boot_entry_free) BootEntry tmp = BOOT_ENTRY_INIT(BOOT_ENTRY_CONF);
        unsigned line = 1;
        char *c;
        int r;

        assert(f);
        assert(root);
        assert(dir);
        assert(fname);
        assert(entry);

        /* Loads a Type #1 boot menu entry from the specified FILE* object */

        r = boot_filename_extract_tries(fname, &tmp.id, &tmp.tries_left, &tmp.tries_done);
        if (r < 0)
                return r;

        if (!efi_loader_entry_name_valid(tmp.id))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid loader entry name: %s", fname);

        c = endswith_no_case(tmp.id, ".conf");
        if (!c)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid loader entry file suffix: %s", fname);

        tmp.id_old = strndup(tmp.id, c - tmp.id); /* Without .conf suffix */
        if (!tmp.id_old)
                return log_oom();

        tmp.path = path_join(dir, fname);
        if (!tmp.path)
                return log_oom();

        tmp.root = strdup(root);
        if (!tmp.root)
                return log_oom();

        for (;;) {
                _cleanup_free_ char *buf = NULL, *field = NULL;

                r = read_stripped_line(f, LONG_LINE_MAX, &buf);
                if (r == 0)
                        break;
                if (r == -ENOBUFS)
                        return log_syntax(NULL, LOG_ERR, tmp.path, line, r, "Line too long.");
                if (r < 0)
                        return log_syntax(NULL, LOG_ERR, tmp.path, line, r, "Error while reading: %m");

                line++;

                if (IN_SET(buf[0], '#', '\0'))
                        continue;

                const char *p = buf;
                r = extract_first_word(&p, &field, NULL, 0);
                if (r < 0) {
                        log_syntax(NULL, LOG_WARNING, tmp.path, line, r, "Failed to parse, ignoring line: %m");
                        continue;
                }
                if (r == 0) {
                        log_syntax(NULL, LOG_WARNING, tmp.path, line, 0, "Bad syntax, ignoring line.");
                        continue;
                }

                if (isempty(p)) {
                        /* Some fields can reasonably have an empty value. In other cases warn. */
                        if (!STR_IN_SET(field, "options", "devicetree-overlay"))
                                log_syntax(NULL, LOG_WARNING, tmp.path, line, 0, "Field '%s' without value, ignoring line.", field);

                        continue;
                }

                if (streq(field, "title"))
                        r = free_and_strdup(&tmp.title, p);
                else if (streq(field, "sort-key"))
                        r = free_and_strdup(&tmp.sort_key, p);
                else if (streq(field, "version"))
                        r = free_and_strdup(&tmp.version, p);
                else if (streq(field, "machine-id"))
                        r = free_and_strdup(&tmp.machine_id, p);
                else if (streq(field, "architecture"))
                        r = free_and_strdup(&tmp.architecture, p);
                else if (streq(field, "options"))
                        r = strv_extend(&tmp.options, p);
                else if (streq(field, "linux"))
                        r = parse_path_one(tmp.path, line, field, &tmp.kernel, p);
                else if (streq(field, "efi"))
                        r = parse_path_one(tmp.path, line, field, &tmp.efi, p);
                else if (streq(field, "initrd"))
                        r = parse_path_strv(tmp.path, line, field, &tmp.initrd, p);
                else if (streq(field, "devicetree"))
                        r = parse_path_one(tmp.path, line, field, &tmp.device_tree, p);
                else if (streq(field, "devicetree-overlay"))
                        r = parse_path_many(tmp.path, line, field, &tmp.device_tree_overlay, p);
                else {
                        log_syntax(NULL, LOG_WARNING, tmp.path, line, 0, "Unknown line '%s', ignoring.", field);
                        continue;
                }
                if (r < 0)
                        return log_syntax(NULL, LOG_ERR, tmp.path, line, r, "Error while parsing: %m");
        }

        *entry = TAKE_STRUCT(tmp);
        return 0;
}

int boot_config_load_type1(
                BootConfig *config,
                FILE *f,
                const char *root,
                const char *dir,
                const char *fname) {
        int r;

        assert(config);
        assert(f);
        assert(root);
        assert(dir);
        assert(fname);

        if (!GREEDY_REALLOC0(config->entries, config->n_entries + 1))
                return log_oom();

        r = boot_entry_load_type1(f, root, dir, fname, config->entries + config->n_entries);
        if (r < 0)
                return r;

        config->n_entries++;
        return 0;
}

void boot_config_free(BootConfig *config) {
        assert(config);

        free(config->default_pattern);
        free(config->timeout);
        free(config->editor);
        free(config->auto_entries);
        free(config->auto_firmware);
        free(config->console_mode);
        free(config->beep);

        free(config->entry_oneshot);
        free(config->entry_default);
        free(config->entry_selected);

        for (size_t i = 0; i < config->n_entries; i++)
                boot_entry_free(config->entries + i);
        free(config->entries);

        set_free(config->inodes_seen);
}

int boot_loader_read_conf(BootConfig *config, FILE *file, const char *path) {
        unsigned line = 1;
        int r;

        assert(config);
        assert(file);
        assert(path);

        for (;;) {
                _cleanup_free_ char *buf = NULL, *field = NULL;

                r = read_stripped_line(file, LONG_LINE_MAX, &buf);
                if (r == 0)
                        break;
                if (r == -ENOBUFS)
                        return log_syntax(NULL, LOG_ERR, path, line, r, "Line too long.");
                if (r < 0)
                        return log_syntax(NULL, LOG_ERR, path, line, r, "Error while reading: %m");

                line++;

                if (IN_SET(buf[0], '#', '\0'))
                        continue;

                const char *p = buf;
                r = extract_first_word(&p, &field, NULL, 0);
                if (r < 0) {
                        log_syntax(NULL, LOG_WARNING, path, line, r, "Failed to parse, ignoring line: %m");
                        continue;
                }
                if (r == 0) {
                        log_syntax(NULL, LOG_WARNING, path, line, 0, "Bad syntax, ignoring line.");
                        continue;
                }
                if (isempty(p)) {
                        log_syntax(NULL, LOG_WARNING, path, line, 0, "Field '%s' without value, ignoring line.", field);
                        continue;
                }

                if (streq(field, "default"))
                        r = free_and_strdup(&config->default_pattern, p);
                else if (streq(field, "timeout"))
                        r = free_and_strdup(&config->timeout, p);
                else if (streq(field, "editor"))
                        r = free_and_strdup(&config->editor, p);
                else if (streq(field, "auto-entries"))
                        r = free_and_strdup(&config->auto_entries, p);
                else if (streq(field, "auto-firmware"))
                        r = free_and_strdup(&config->auto_firmware, p);
                else if (streq(field, "console-mode"))
                        r = free_and_strdup(&config->console_mode, p);
                else if (streq(field, "random-seed-mode"))
                        log_syntax(NULL, LOG_WARNING, path, line, 0, "'random-seed-mode' has been deprecated, ignoring.");
                else if (streq(field, "beep"))
                        r = free_and_strdup(&config->beep, p);
                else {
                        log_syntax(NULL, LOG_WARNING, path, line, 0, "Unknown line '%s', ignoring.", field);
                        continue;
                }
                if (r < 0)
                        return log_syntax(NULL, LOG_ERR, path, line, r, "Error while parsing: %m");
        }

        return 1;
}

static int boot_loader_read_conf_path(BootConfig *config, const char *root, const char *path) {
        _cleanup_free_ char *full = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(config);
        assert(path);

        r = chase_and_fopen_unlocked(path, root, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS, "re", &full, &f);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to open '%s/%s': %m", root, path);

        return boot_loader_read_conf(config, f, full);
}

static int boot_entry_compare(const BootEntry *a, const BootEntry *b) {
        int r;

        assert(a);
        assert(b);

        r = CMP(!a->sort_key, !b->sort_key);
        if (r != 0)
                return r;

        if (a->sort_key && b->sort_key) {
                r = strcmp(a->sort_key, b->sort_key);
                if (r != 0)
                        return r;

                r = strcmp_ptr(a->machine_id, b->machine_id);
                if (r != 0)
                        return r;

                r = -strverscmp_improved(a->version, b->version);
                if (r != 0)
                        return r;
        }

        return -strverscmp_improved(a->id, b->id);
}

static int config_check_inode_relevant_and_unseen(BootConfig *config, int fd, const char *fname) {
        _cleanup_free_ char *d = NULL;
        struct stat st;

        assert(config);
        assert(fd >= 0);
        assert(fname);

        /* So, here's the thing: because of the mess around /efi/ vs. /boot/ vs. /boot/efi/ it might be that
         * people have these dirs, or subdirs of them symlinked or bind mounted, and we might end up
         * iterating though some dirs multiple times. Let's thus rather be safe than sorry, and track the
         * inodes we already processed: let's ignore inodes we have seen already. This should be robust
         * against any form of symlinking or bind mounting, and effectively suppress any such duplicates. */

        if (fstat(fd, &st) < 0)
                return log_error_errno(errno, "Failed to stat('%s'): %m", fname);
        if (!S_ISREG(st.st_mode)) {
                log_debug("File '%s' is not a regular file, ignoring.", fname);
                return false;
        }

        if (set_contains(config->inodes_seen, &st)) {
                log_debug("Inode '%s' already seen before, ignoring.", fname);
                return false;
        }

        d = memdup(&st, sizeof(st));
        if (!d)
                return log_oom();

        if (set_ensure_consume(&config->inodes_seen, &inode_hash_ops, TAKE_PTR(d)) < 0)
                return log_oom();

        return true;
}

static int boot_entries_find_type1(
                BootConfig *config,
                const char *root,
                const char *dir) {

        _cleanup_free_ DirectoryEntries *dentries = NULL;
        _cleanup_free_ char *full = NULL;
        _cleanup_close_ int dir_fd = -EBADF;
        int r;

        assert(config);
        assert(root);
        assert(dir);

        dir_fd = chase_and_open(dir, root, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS, O_DIRECTORY|O_CLOEXEC, &full);
        if (dir_fd == -ENOENT)
                return 0;
        if (dir_fd < 0)
                return log_error_errno(dir_fd, "Failed to open '%s/%s': %m", root, dir);

        r = readdir_all(dir_fd, RECURSE_DIR_IGNORE_DOT, &dentries);
        if (r < 0)
                return log_error_errno(r, "Failed to read directory '%s': %m", full);

        for (size_t i = 0; i < dentries->n_entries; i++) {
                const struct dirent *de = dentries->entries[i];
                _cleanup_fclose_ FILE *f = NULL;

                if (!dirent_is_file(de))
                        continue;

                if (!endswith_no_case(de->d_name, ".conf"))
                        continue;

                r = xfopenat(dir_fd, de->d_name, "re", O_NOFOLLOW|O_NOCTTY, &f);
                if (r < 0) {
                        log_warning_errno(r, "Failed to open %s/%s, ignoring: %m", full, de->d_name);
                        continue;
                }

                r = config_check_inode_relevant_and_unseen(config, fileno(f), de->d_name);
                if (r < 0)
                        return r;
                if (r == 0) /* inode already seen or otherwise not relevant */
                        continue;

                r = boot_config_load_type1(config, f, root, full, de->d_name);
                if (r == -ENOMEM) /* ignore all other errors */
                        return r;
        }

        return 0;
}

static int boot_entry_load_unified(
                const char *root,
                const char *path,
                const char *osrelease,
                const char *cmdline,
                BootEntry *ret) {

        _cleanup_free_ char *fname = NULL, *os_pretty_name = NULL, *os_image_id = NULL, *os_name = NULL, *os_id = NULL,
                *os_image_version = NULL, *os_version = NULL, *os_version_id = NULL, *os_build_id = NULL;
        _cleanup_(boot_entry_free) BootEntry tmp = BOOT_ENTRY_INIT(BOOT_ENTRY_UNIFIED);
        const char *k, *good_name, *good_version, *good_sort_key;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(root);
        assert(path);
        assert(osrelease);

        k = path_startswith(path, root);
        if (!k)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Path is not below root: %s", path);

        f = fmemopen_unlocked((void*) osrelease, strlen(osrelease), "r");
        if (!f)
                return log_error_errno(errno, "Failed to open os-release buffer: %m");

        r = parse_env_file(f, "os-release",
                           "PRETTY_NAME", &os_pretty_name,
                           "IMAGE_ID", &os_image_id,
                           "NAME", &os_name,
                           "ID", &os_id,
                           "IMAGE_VERSION", &os_image_version,
                           "VERSION", &os_version,
                           "VERSION_ID", &os_version_id,
                           "BUILD_ID", &os_build_id);
        if (r < 0)
                return log_error_errno(r, "Failed to parse os-release data from unified kernel image %s: %m", path);

        if (!bootspec_pick_name_version_sort_key(
                            os_pretty_name,
                            os_image_id,
                            os_name,
                            os_id,
                            os_image_version,
                            os_version,
                            os_version_id,
                            os_build_id,
                            &good_name,
                            &good_version,
                            &good_sort_key))
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Missing fields in os-release data from unified kernel image %s, refusing.", path);

        r = path_extract_filename(path, &fname);
        if (r < 0)
                return log_error_errno(r, "Failed to extract file name from '%s': %m", path);

        r = boot_filename_extract_tries(fname, &tmp.id, &tmp.tries_left, &tmp.tries_done);
        if (r < 0)
                return r;

        if (!efi_loader_entry_name_valid(tmp.id))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid loader entry name: %s", tmp.id);

        if (os_id && os_version_id) {
                tmp.id_old = strjoin(os_id, "-", os_version_id);
                if (!tmp.id_old)
                        return log_oom();
        }

        tmp.path = strdup(path);
        if (!tmp.path)
                return log_oom();

        tmp.root = strdup(root);
        if (!tmp.root)
                return log_oom();

        tmp.kernel = path_make_absolute(k, "/");
        if (!tmp.kernel)
                return log_oom();

        tmp.options = strv_new(skip_leading_chars(cmdline, WHITESPACE));
        if (!tmp.options)
                return log_oom();

        delete_trailing_chars(tmp.options[0], WHITESPACE);

        tmp.title = strdup(good_name);
        if (!tmp.title)
                return log_oom();

        if (good_sort_key) {
                tmp.sort_key = strdup(good_sort_key);
                if (!tmp.sort_key)
                        return log_oom();
        }

        if (good_version) {
                tmp.version = strdup(good_version);
                if (!tmp.version)
                        return log_oom();
        }

        *ret = TAKE_STRUCT(tmp);
        return 0;
}

/* Maximum PE section we are willing to load (Note that sections we are not interested in may be larger, but
 * the ones we do care about and we are willing to load into memory have this size limit.) */
#define PE_SECTION_SIZE_MAX (4U*1024U*1024U)

static int find_sections(
                int fd,
                const char *path,
                char **ret_osrelease,
                char **ret_cmdline) {

        _cleanup_free_ IMAGE_SECTION_HEADER *sections = NULL;
        _cleanup_free_ IMAGE_DOS_HEADER *dos_header = NULL;
        _cleanup_free_ char *osrel = NULL, *cmdline = NULL;
        _cleanup_free_ PeHeader *pe_header = NULL;
        int r;

        assert(fd >= 0);
        assert(path);

        r = pe_load_headers(fd, &dos_header, &pe_header);
        if (r < 0)
                return log_warning_errno(r, "Failed to parse PE file '%s': %m", path);

        r = pe_load_sections(fd, dos_header, pe_header, &sections);
        if (r < 0)
                return log_warning_errno(r, "Failed to parse PE sections of '%s': %m", path);

        if (!pe_is_uki(pe_header, sections))
                return log_warning_errno(SYNTHETIC_ERRNO(EBADMSG), "Parsed PE file '%s' is not a UKI.", path);

        r = pe_read_section_data(fd, pe_header, sections, ".osrel", PE_SECTION_SIZE_MAX, (void**) &osrel, NULL);
        if (r < 0)
                return log_warning_errno(r, "Failed to read .osrel section of '%s': %m", path);

        r = pe_read_section_data(fd, pe_header, sections, ".cmdline", PE_SECTION_SIZE_MAX, (void**) &cmdline, NULL);
        if (r < 0 && r != -ENXIO) /* cmdline is optional */
                return log_warning_errno(r, "Failed to read .cmdline section of '%s': %m", path);

        if (ret_osrelease)
                *ret_osrelease = TAKE_PTR(osrel);
        if (ret_cmdline)
                *ret_cmdline = TAKE_PTR(cmdline);

        return 0;
}

static int boot_entries_find_unified(
                BootConfig *config,
                const char *root,
                const char *dir) {

        _cleanup_closedir_ DIR *d = NULL;
        _cleanup_free_ char *full = NULL;
        int r;

        assert(config);
        assert(dir);

        r = chase_and_opendir(dir, root, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS, &full, &d);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to open '%s/%s': %m", root, dir);

        FOREACH_DIRENT(de, d, return log_error_errno(errno, "Failed to read %s: %m", full)) {
                _cleanup_free_ char *j = NULL, *osrelease = NULL, *cmdline = NULL;
                _cleanup_close_ int fd = -EBADF;

                if (!dirent_is_file(de))
                        continue;

                if (!endswith_no_case(de->d_name, ".efi"))
                        continue;

                if (!GREEDY_REALLOC0(config->entries, config->n_entries + 1))
                        return log_oom();

                fd = openat(dirfd(d), de->d_name, O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOFOLLOW|O_NOCTTY);
                if (fd < 0) {
                        log_warning_errno(errno, "Failed to open %s/%s, ignoring: %m", full, de->d_name);
                        continue;
                }

                r = config_check_inode_relevant_and_unseen(config, fd, de->d_name);
                if (r < 0)
                        return r;
                if (r == 0) /* inode already seen or otherwise not relevant */
                        continue;

                j = path_join(full, de->d_name);
                if (!j)
                        return log_oom();

                if (find_sections(fd, j, &osrelease, &cmdline) < 0)
                        continue;

                r = boot_entry_load_unified(root, j, osrelease, cmdline, config->entries + config->n_entries);
                if (r < 0)
                        continue;

                config->n_entries++;
        }

        return 0;
}

static bool find_nonunique(const BootEntry *entries, size_t n_entries, bool arr[]) {
        bool non_unique = false;

        assert(entries || n_entries == 0);
        assert(arr || n_entries == 0);

        for (size_t i = 0; i < n_entries; i++)
                arr[i] = false;

        for (size_t i = 0; i < n_entries; i++)
                for (size_t j = 0; j < n_entries; j++)
                        if (i != j && streq(boot_entry_title(entries + i),
                                            boot_entry_title(entries + j)))
                                non_unique = arr[i] = arr[j] = true;

        return non_unique;
}

static int boot_entries_uniquify(BootEntry *entries, size_t n_entries) {
        _cleanup_free_ bool *arr = NULL;
        char *s;

        assert(entries || n_entries == 0);

        if (n_entries == 0)
                return 0;

        arr = new(bool, n_entries);
        if (!arr)
                return -ENOMEM;

        /* Find _all_ non-unique titles */
        if (!find_nonunique(entries, n_entries, arr))
                return 0;

        /* Add version to non-unique titles */
        for (size_t i = 0; i < n_entries; i++)
                if (arr[i] && entries[i].version) {
                        if (asprintf(&s, "%s (%s)", boot_entry_title(entries + i), entries[i].version) < 0)
                                return -ENOMEM;

                        free_and_replace(entries[i].show_title, s);
                }

        if (!find_nonunique(entries, n_entries, arr))
                return 0;

        /* Add machine-id to non-unique titles */
        for (size_t i = 0; i < n_entries; i++)
                if (arr[i] && entries[i].machine_id) {
                        if (asprintf(&s, "%s (%s)", boot_entry_title(entries + i), entries[i].machine_id) < 0)
                                return -ENOMEM;

                        free_and_replace(entries[i].show_title, s);
                }

        if (!find_nonunique(entries, n_entries, arr))
                return 0;

        /* Add file name to non-unique titles */
        for (size_t i = 0; i < n_entries; i++)
                if (arr[i]) {
                        if (asprintf(&s, "%s (%s)", boot_entry_title(entries + i), entries[i].id) < 0)
                                return -ENOMEM;

                        free_and_replace(entries[i].show_title, s);
                }

        return 0;
}

static int boot_config_find(const BootConfig *config, const char *id) {
        assert(config);

        if (!id)
                return -1;

        if (id[0] == '@') {
                if (!strcaseeq(id, "@saved"))
                        return -1;
                if (!config->entry_selected)
                        return -1;
                id = config->entry_selected;
        }

        for (size_t i = 0; i < config->n_entries; i++)
                if (fnmatch(id, config->entries[i].id, FNM_CASEFOLD) == 0)
                        return i;

        return -1;
}

static int boot_entries_select_default(const BootConfig *config) {
        int i;

        assert(config);
        assert(config->entries || config->n_entries == 0);

        if (config->n_entries == 0) {
                log_debug("Found no default boot entry :(");
                return -1; /* -1 means "no default" */
        }

        if (config->entry_oneshot) {
                i = boot_config_find(config, config->entry_oneshot);
                if (i >= 0) {
                        log_debug("Found default: id \"%s\" is matched by LoaderEntryOneShot",
                                  config->entries[i].id);
                        return i;
                }
        }

        if (config->entry_default) {
                i = boot_config_find(config, config->entry_default);
                if (i >= 0) {
                        log_debug("Found default: id \"%s\" is matched by LoaderEntryDefault",
                                  config->entries[i].id);
                        return i;
                }
        }

        if (config->default_pattern) {
                i = boot_config_find(config, config->default_pattern);
                if (i >= 0) {
                        log_debug("Found default: id \"%s\" is matched by pattern \"%s\"",
                                  config->entries[i].id, config->default_pattern);
                        return i;
                }
        }

        log_debug("Found default: first entry \"%s\"", config->entries[0].id);
        return 0;
}

static int boot_entries_select_selected(const BootConfig *config) {
        assert(config);
        assert(config->entries || config->n_entries == 0);

        if (!config->entry_selected || config->n_entries == 0)
                return -1;

        return boot_config_find(config, config->entry_selected);
}

static int boot_load_efi_entry_pointers(BootConfig *config, bool skip_efivars) {
        int r;

        assert(config);

        if (skip_efivars || !is_efi_boot())
                return 0;

        /* Loads the three "pointers" to boot loader entries from their EFI variables */

        r = efi_get_variable_string(EFI_LOADER_VARIABLE(LoaderEntryOneShot), &config->entry_oneshot);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0 && !IN_SET(r, -ENOENT, -ENODATA))
                log_warning_errno(r, "Failed to read EFI variable \"LoaderEntryOneShot\", ignoring: %m");

        r = efi_get_variable_string(EFI_LOADER_VARIABLE(LoaderEntryDefault), &config->entry_default);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0 && !IN_SET(r, -ENOENT, -ENODATA))
                log_warning_errno(r, "Failed to read EFI variable \"LoaderEntryDefault\", ignoring: %m");

        r = efi_get_variable_string(EFI_LOADER_VARIABLE(LoaderEntrySelected), &config->entry_selected);
        if (r == -ENOMEM)
                return log_oom();
        if (r < 0 && !IN_SET(r, -ENOENT, -ENODATA))
                log_warning_errno(r, "Failed to read EFI variable \"LoaderEntrySelected\", ignoring: %m");

        return 1;
}

int boot_config_select_special_entries(BootConfig *config, bool skip_efivars) {
        int r;

        assert(config);

        r = boot_load_efi_entry_pointers(config, skip_efivars);
        if (r < 0)
                return r;

        config->default_entry = boot_entries_select_default(config);
        config->selected_entry = boot_entries_select_selected(config);

        return 0;
}

int boot_config_finalize(BootConfig *config) {
        int r;

        typesafe_qsort(config->entries, config->n_entries, boot_entry_compare);

        r = boot_entries_uniquify(config->entries, config->n_entries);
        if (r < 0)
                return log_error_errno(r, "Failed to uniquify boot entries: %m");

        return 0;
}

int boot_config_load(
                BootConfig *config,
                const char *esp_path,
                const char *xbootldr_path) {

        int r;

        assert(config);

        if (esp_path) {
                r = boot_loader_read_conf_path(config, esp_path, "/loader/loader.conf");
                if (r < 0)
                        return r;

                r = boot_entries_find_type1(config, esp_path, "/loader/entries");
                if (r < 0)
                        return r;

                r = boot_entries_find_unified(config, esp_path, "/EFI/Linux/");
                if (r < 0)
                        return r;
        }

        if (xbootldr_path) {
                r = boot_entries_find_type1(config, xbootldr_path, "/loader/entries");
                if (r < 0)
                        return r;

                r = boot_entries_find_unified(config, xbootldr_path, "/EFI/Linux/");
                if (r < 0)
                        return r;
        }

        return boot_config_finalize(config);
}

int boot_config_load_auto(
                BootConfig *config,
                const char *override_esp_path,
                const char *override_xbootldr_path) {

        _cleanup_free_ char *esp_where = NULL, *xbootldr_where = NULL;
        dev_t esp_devid = 0, xbootldr_devid = 0;
        int r;

        assert(config);

        /* This function is similar to boot_entries_load_config(), however we automatically search for the
         * ESP and the XBOOTLDR partition unless it is explicitly specified. Also, if the user did not pass
         * an ESP or XBOOTLDR path directly, let's see if /run/boot-loader-entries/ exists. If so, let's
         * read data from there, as if it was an ESP (i.e. loading both entries and loader.conf data from
         * it). This allows other boot loaders to pass boot loader entry information to our tools if they
         * want to. */

        if (!override_esp_path && !override_xbootldr_path) {
                if (access("/run/boot-loader-entries/", F_OK) >= 0)
                        return boot_config_load(config, "/run/boot-loader-entries/", NULL);

                if (errno != ENOENT)
                        return log_error_errno(errno,
                                               "Failed to determine whether /run/boot-loader-entries/ exists: %m");
        }

        r = find_esp_and_warn(NULL, override_esp_path, /* unprivileged_mode= */ false, &esp_where, NULL, NULL, NULL, NULL, &esp_devid);
        if (r < 0) /* we don't log about ENOKEY here, but propagate it, leaving it to the caller to log */
                return r;

        r = find_xbootldr_and_warn(NULL, override_xbootldr_path, /* unprivileged_mode= */ false, &xbootldr_where, NULL, &xbootldr_devid);
        if (r < 0 && r != -ENOKEY)
                return r; /* It's fine if the XBOOTLDR partition doesn't exist, hence we ignore ENOKEY here */

        /* If both paths actually refer to the same inode, suppress the xbootldr path */
        if (esp_where && xbootldr_where && devnum_set_and_equal(esp_devid, xbootldr_devid))
                xbootldr_where = mfree(xbootldr_where);

        return boot_config_load(config, esp_where, xbootldr_where);
}

int boot_config_augment_from_loader(
                BootConfig *config,
                char **found_by_loader,
                bool only_auto) {

        static const char *const title_table[] = {
                /* Pretty names for a few well-known automatically discovered entries. */
                "auto-osx",                      "macOS",
                "auto-windows",                  "Windows Boot Manager",
                "auto-efi-shell",                "EFI Shell",
                "auto-efi-default",              "EFI Default Loader",
                "auto-poweroff",                 "Power Off The System",
                "auto-reboot",                   "Reboot The System",
                "auto-reboot-to-firmware-setup", "Reboot Into Firmware Interface",
                NULL,
        };

        assert(config);

        /* Let's add the entries discovered by the boot loader to the end of our list, unless they are
         * already included there. */

        STRV_FOREACH(i, found_by_loader) {
                BootEntry *existing;
                _cleanup_free_ char *c = NULL, *t = NULL, *p = NULL;

                existing = boot_config_find_entry(config, *i);
                if (existing) {
                        existing->reported_by_loader = true;
                        continue;
                }

                if (only_auto && !startswith(*i, "auto-"))
                        continue;

                c = strdup(*i);
                if (!c)
                        return log_oom();

                STRV_FOREACH_PAIR(a, b, title_table)
                        if (streq(*a, *i)) {
                                t = strdup(*b);
                                if (!t)
                                        return log_oom();
                                break;
                        }

                p = strdup(EFIVAR_PATH(EFI_LOADER_VARIABLE(LoaderEntries)));
                if (!p)
                        return log_oom();

                if (!GREEDY_REALLOC0(config->entries, config->n_entries + 1))
                        return log_oom();

                config->entries[config->n_entries++] = (BootEntry) {
                        .type = startswith(*i, "auto-") ? BOOT_ENTRY_LOADER_AUTO : BOOT_ENTRY_LOADER,
                        .id = TAKE_PTR(c),
                        .title = TAKE_PTR(t),
                        .path = TAKE_PTR(p),
                        .reported_by_loader = true,
                        .tries_left = UINT_MAX,
                        .tries_done = UINT_MAX,
                };
        }

        return 0;
}

BootEntry* boot_config_find_entry(BootConfig *config, const char *id) {
        assert(config);
        assert(id);

        for (size_t j = 0; j < config->n_entries; j++)
                if (strcaseeq_ptr(config->entries[j].id, id) ||
                    strcaseeq_ptr(config->entries[j].id_old, id))
                        return config->entries + j;

        return NULL;
}

static void boot_entry_file_list(
                const char *field,
                const char *root,
                const char *p,
                int *ret_status) {

        assert(p);
        assert(ret_status);

        int status = chase_and_access(p, root, CHASE_PREFIX_ROOT|CHASE_PROHIBIT_SYMLINKS, F_OK, NULL);

        /* Note that this shows two '/' between the root and the file. This is intentional to highlight (in
         * the absence of color support) to the user that the boot loader is only interested in the second
         * part of the file. */
        printf("%13s%s %s%s/%s", strempty(field), field ? ":" : " ", ansi_grey(), root, ansi_normal());

        if (status < 0) {
                errno = -status;
                printf("%s%s%s (%m)\n", ansi_highlight_red(), p, ansi_normal());
        } else
                printf("%s\n", p);

        if (*ret_status == 0 && status < 0)
                *ret_status = status;
}

int show_boot_entry(
                const BootEntry *e,
                bool show_as_default,
                bool show_as_selected,
                bool show_reported) {

        int status = 0;

        /* Returns 0 on success, negative on processing error, and positive if something is wrong with the
           boot entry itself. */

        assert(e);

        printf("         type: %s\n",
               boot_entry_type_to_string(e->type));

        printf("        title: %s%s%s",
               ansi_highlight(), boot_entry_title(e), ansi_normal());

        if (show_as_default)
                printf(" %s(default)%s",
                       ansi_highlight_green(), ansi_normal());

        if (show_as_selected)
                printf(" %s(selected)%s",
                       ansi_highlight_magenta(), ansi_normal());

        if (show_reported) {
                if (e->type == BOOT_ENTRY_LOADER)
                        printf(" %s(reported/absent)%s",
                               ansi_highlight_red(), ansi_normal());
                else if (!e->reported_by_loader && e->type != BOOT_ENTRY_LOADER_AUTO)
                        printf(" %s(not reported/new)%s",
                               ansi_highlight_green(), ansi_normal());
        }

        putchar('\n');

        if (e->id)
                printf("           id: %s\n", e->id);
        if (e->path) {
                _cleanup_free_ char *text = NULL, *link = NULL;

                const char *p = e->root ? path_startswith(e->path, e->root) : NULL;
                if (p) {
                        text = strjoin(ansi_grey(), e->root, "/", ansi_normal(), "/", p);
                        if (!text)
                                return log_oom();
                }

                /* Let's urlify the link to make it easy to view in an editor, but only if it is a text
                 * file. Unified images are binary ELFs, and EFI variables are not pure text either. */
                if (e->type == BOOT_ENTRY_CONF)
                        (void) terminal_urlify_path(e->path, text, &link);

                printf("       source: %s\n", link ?: text ?: e->path);
        }
        if (e->tries_left != UINT_MAX) {
                printf("        tries: %u left", e->tries_left);

                if (e->tries_done != UINT_MAX)
                        printf("; %u done\n", e->tries_done);
                else
                        printf("\n");
        }

        if (e->sort_key)
                printf("     sort-key: %s\n", e->sort_key);
        if (e->version)
                printf("      version: %s\n", e->version);
        if (e->machine_id)
                printf("   machine-id: %s\n", e->machine_id);
        if (e->architecture)
                printf(" architecture: %s\n", e->architecture);
        if (e->kernel)
                boot_entry_file_list("linux", e->root, e->kernel, &status);
        if (e->efi)
                boot_entry_file_list("efi", e->root, e->efi, &status);

        STRV_FOREACH(s, e->initrd)
                boot_entry_file_list(s == e->initrd ? "initrd" : NULL,
                                     e->root,
                                     *s,
                                     &status);

        if (!strv_isempty(e->options)) {
                _cleanup_free_ char *t = NULL, *t2 = NULL;
                _cleanup_strv_free_ char **ts = NULL;

                t = strv_join(e->options, " ");
                if (!t)
                        return log_oom();

                ts = strv_split_newlines(t);
                if (!ts)
                        return log_oom();

                t2 = strv_join(ts, "\n              ");
                if (!t2)
                        return log_oom();

                printf("      options: %s\n", t2);
        }

        if (e->device_tree)
                boot_entry_file_list("devicetree", e->root, e->device_tree, &status);

        STRV_FOREACH(s, e->device_tree_overlay)
                boot_entry_file_list(s == e->device_tree_overlay ? "devicetree-overlay" : NULL,
                                     e->root,
                                     *s,
                                     &status);

        return -status;
}

int show_boot_entries(const BootConfig *config, JsonFormatFlags json_format) {
        int r;

        assert(config);

        if (!FLAGS_SET(json_format, JSON_FORMAT_OFF)) {
                _cleanup_(json_variant_unrefp) JsonVariant *array = NULL;

                for (size_t i = 0; i < config->n_entries; i++) {
                        _cleanup_free_ char *opts = NULL;
                        const BootEntry *e = config->entries + i;
                        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;

                        if (!strv_isempty(e->options)) {
                                opts = strv_join(e->options, " ");
                                if (!opts)
                                        return log_oom();
                        }

                        r = json_variant_merge_objectb(
                                        &v, JSON_BUILD_OBJECT(
                                                       JSON_BUILD_PAIR("type", JSON_BUILD_STRING(boot_entry_type_json_to_string(e->type))),
                                                       JSON_BUILD_PAIR_CONDITION(e->id, "id", JSON_BUILD_STRING(e->id)),
                                                       JSON_BUILD_PAIR_CONDITION(e->path, "path", JSON_BUILD_STRING(e->path)),
                                                       JSON_BUILD_PAIR_CONDITION(e->root, "root", JSON_BUILD_STRING(e->root)),
                                                       JSON_BUILD_PAIR_CONDITION(e->title, "title", JSON_BUILD_STRING(e->title)),
                                                       JSON_BUILD_PAIR_CONDITION(boot_entry_title(e), "showTitle", JSON_BUILD_STRING(boot_entry_title(e))),
                                                       JSON_BUILD_PAIR_CONDITION(e->sort_key, "sortKey", JSON_BUILD_STRING(e->sort_key)),
                                                       JSON_BUILD_PAIR_CONDITION(e->version, "version", JSON_BUILD_STRING(e->version)),
                                                       JSON_BUILD_PAIR_CONDITION(e->machine_id, "machineId", JSON_BUILD_STRING(e->machine_id)),
                                                       JSON_BUILD_PAIR_CONDITION(e->architecture, "architecture", JSON_BUILD_STRING(e->architecture)),
                                                       JSON_BUILD_PAIR_CONDITION(opts, "options", JSON_BUILD_STRING(opts)),
                                                       JSON_BUILD_PAIR_CONDITION(e->kernel, "linux", JSON_BUILD_STRING(e->kernel)),
                                                       JSON_BUILD_PAIR_CONDITION(e->efi, "efi", JSON_BUILD_STRING(e->efi)),
                                                       JSON_BUILD_PAIR_CONDITION(!strv_isempty(e->initrd), "initrd", JSON_BUILD_STRV(e->initrd)),
                                                       JSON_BUILD_PAIR_CONDITION(e->device_tree, "devicetree", JSON_BUILD_STRING(e->device_tree)),
                                                       JSON_BUILD_PAIR_CONDITION(!strv_isempty(e->device_tree_overlay), "devicetreeOverlay", JSON_BUILD_STRV(e->device_tree_overlay))));
                        if (r < 0)
                                return log_oom();

                        /* Sanitizers (only memory sanitizer?) do not like function call with too many
                         * arguments and trigger false positive warnings. Let's not add too many json objects
                         * at once. */
                        r = json_variant_merge_objectb(
                                        &v, JSON_BUILD_OBJECT(
                                                       JSON_BUILD_PAIR("isReported", JSON_BUILD_BOOLEAN(e->reported_by_loader)),
                                                       JSON_BUILD_PAIR_CONDITION(e->tries_left != UINT_MAX, "triesLeft", JSON_BUILD_UNSIGNED(e->tries_left)),
                                                       JSON_BUILD_PAIR_CONDITION(e->tries_done != UINT_MAX, "triesDone", JSON_BUILD_UNSIGNED(e->tries_done)),
                                                       JSON_BUILD_PAIR_CONDITION(config->default_entry >= 0, "isDefault", JSON_BUILD_BOOLEAN(i == (size_t) config->default_entry)),
                                                       JSON_BUILD_PAIR_CONDITION(config->selected_entry >= 0, "isSelected", JSON_BUILD_BOOLEAN(i == (size_t) config->selected_entry))));

                        if (r < 0)
                                return log_oom();

                        r = json_variant_append_array(&array, v);
                        if (r < 0)
                                return log_oom();
                }

                json_variant_dump(array, json_format | JSON_FORMAT_EMPTY_ARRAY, NULL, NULL);

        } else {
                for (size_t n = 0; n < config->n_entries; n++) {
                        r = show_boot_entry(
                                        config->entries + n,
                                        /* show_as_default= */  n == (size_t) config->default_entry,
                                        /* show_as_selected= */ n == (size_t) config->selected_entry,
                                        /* show_discovered= */  true);
                        if (r < 0)
                                return r;

                        if (n+1 < config->n_entries)
                                putchar('\n');
                }
        }

        return 0;
}
