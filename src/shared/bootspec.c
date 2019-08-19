/* SPDX-License-Identifier: LGPL-2.1+ */

#include <stdio.h>
#include <linux/magic.h>
#include <unistd.h>

#include "sd-device.h"
#include "sd-id128.h"

#include "alloc-util.h"
#include "blkid-util.h"
#include "bootspec.h"
#include "conf-files.h"
#include "def.h"
#include "device-nodes.h"
#include "dirent-util.h"
#include "efivars.h"
#include "env-file.h"
#include "env-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "parse-util.h"
#include "path-util.h"
#include "pe-header.h"
#include "sort-util.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "unaligned.h"
#include "util.h"
#include "virt.h"

static void boot_entry_free(BootEntry *entry) {
        assert(entry);

        free(entry->id);
        free(entry->path);
        free(entry->root);
        free(entry->title);
        free(entry->show_title);
        free(entry->version);
        free(entry->machine_id);
        free(entry->architecture);
        strv_free(entry->options);
        free(entry->kernel);
        free(entry->efi);
        strv_free(entry->initrd);
        free(entry->device_tree);
}

static int boot_entry_load(
                const char *root,
                const char *path,
                BootEntry *entry) {

        _cleanup_(boot_entry_free) BootEntry tmp = {
                .type = BOOT_ENTRY_CONF,
        };

        _cleanup_fclose_ FILE *f = NULL;
        unsigned line = 1;
        char *b, *c;
        int r;

        assert(root);
        assert(path);
        assert(entry);

        c = endswith_no_case(path, ".conf");
        if (!c)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid loader entry file suffix: %s", path);

        b = basename(path);
        tmp.id = strndup(b, c - b);
        if (!tmp.id)
                return log_oom();

        if (!efi_loader_entry_name_valid(tmp.id))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid loader entry filename: %s", path);

        tmp.path = strdup(path);
        if (!tmp.path)
                return log_oom();

        tmp.root = strdup(root);
        if (!tmp.root)
                return log_oom();

        f = fopen(path, "re");
        if (!f)
                return log_error_errno(errno, "Failed to open \"%s\": %m", path);

        for (;;) {
                _cleanup_free_ char *buf = NULL, *field = NULL;
                const char *p;

                r = read_line(f, LONG_LINE_MAX, &buf);
                if (r == 0)
                        break;
                if (r == -ENOBUFS)
                        return log_error_errno(r, "%s:%u: Line too long", path, line);
                if (r < 0)
                        return log_error_errno(r, "%s:%u: Error while reading: %m", path, line);

                line++;

                if (IN_SET(*strstrip(buf), '#', '\0'))
                        continue;

                p = buf;
                r = extract_first_word(&p, &field, " \t", 0);
                if (r < 0) {
                        log_error_errno(r, "Failed to parse config file %s line %u: %m", path, line);
                        continue;
                }
                if (r == 0) {
                        log_warning("%s:%u: Bad syntax", path, line);
                        continue;
                }

                if (streq(field, "title"))
                        r = free_and_strdup(&tmp.title, p);
                else if (streq(field, "version"))
                        r = free_and_strdup(&tmp.version, p);
                else if (streq(field, "machine-id"))
                        r = free_and_strdup(&tmp.machine_id, p);
                else if (streq(field, "architecture"))
                        r = free_and_strdup(&tmp.architecture, p);
                else if (streq(field, "options"))
                        r = strv_extend(&tmp.options, p);
                else if (streq(field, "linux"))
                        r = free_and_strdup(&tmp.kernel, p);
                else if (streq(field, "efi"))
                        r = free_and_strdup(&tmp.efi, p);
                else if (streq(field, "initrd"))
                        r = strv_extend(&tmp.initrd, p);
                else if (streq(field, "devicetree"))
                        r = free_and_strdup(&tmp.device_tree, p);
                else {
                        log_notice("%s:%u: Unknown line \"%s\", ignoring.", path, line, field);
                        continue;
                }
                if (r < 0)
                        return log_error_errno(r, "%s:%u: Error while reading: %m", path, line);
        }

        *entry = tmp;
        tmp = (BootEntry) {};
        return 0;
}

void boot_config_free(BootConfig *config) {
        size_t i;

        assert(config);

        free(config->default_pattern);
        free(config->timeout);
        free(config->editor);
        free(config->auto_entries);
        free(config->auto_firmware);
        free(config->console_mode);

        free(config->entry_oneshot);
        free(config->entry_default);

        for (i = 0; i < config->n_entries; i++)
                boot_entry_free(config->entries + i);
        free(config->entries);
}

static int boot_loader_read_conf(const char *path, BootConfig *config) {
        _cleanup_fclose_ FILE *f = NULL;
        unsigned line = 1;
        int r;

        assert(path);
        assert(config);

        f = fopen(path, "re");
        if (!f) {
                if (errno == ENOENT)
                        return 0;

                return log_error_errno(errno, "Failed to open \"%s\": %m", path);
        }

        for (;;) {
                _cleanup_free_ char *buf = NULL, *field = NULL;
                const char *p;

                r = read_line(f, LONG_LINE_MAX, &buf);
                if (r == 0)
                        break;
                if (r == -ENOBUFS)
                        return log_error_errno(r, "%s:%u: Line too long", path, line);
                if (r < 0)
                        return log_error_errno(r, "%s:%u: Error while reading: %m", path, line);

                line++;

                if (IN_SET(*strstrip(buf), '#', '\0'))
                        continue;

                p = buf;
                r = extract_first_word(&p, &field, " \t", 0);
                if (r < 0) {
                        log_error_errno(r, "Failed to parse config file %s line %u: %m", path, line);
                        continue;
                }
                if (r == 0) {
                        log_warning("%s:%u: Bad syntax", path, line);
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
                else {
                        log_notice("%s:%u: Unknown line \"%s\", ignoring.", path, line, field);
                        continue;
                }
                if (r < 0)
                        return log_error_errno(r, "%s:%u: Error while reading: %m", path, line);
        }

        return 1;
}

static int boot_entry_compare(const BootEntry *a, const BootEntry *b) {
        return str_verscmp(a->id, b->id);
}

static int boot_entries_find(
                const char *root,
                const char *dir,
                BootEntry **entries,
                size_t *n_entries) {

        _cleanup_strv_free_ char **files = NULL;
        size_t n_allocated = *n_entries;
        char **f;
        int r;

        assert(root);
        assert(dir);
        assert(entries);
        assert(n_entries);

        r = conf_files_list(&files, ".conf", NULL, 0, dir);
        if (r < 0)
                return log_error_errno(r, "Failed to list files in \"%s\": %m", dir);

        STRV_FOREACH(f, files) {
                if (!GREEDY_REALLOC0(*entries, n_allocated, *n_entries + 1))
                        return log_oom();

                r = boot_entry_load(root, *f, *entries + *n_entries);
                if (r < 0)
                        continue;

                (*n_entries) ++;
        }

        return 0;
}

static int boot_entry_load_unified(
                const char *root,
                const char *path,
                const char *osrelease,
                const char *cmdline,
                BootEntry *ret) {

        _cleanup_free_ char *os_pretty_name = NULL, *os_id = NULL, *version_id = NULL, *build_id = NULL;
        _cleanup_(boot_entry_free) BootEntry tmp = {
                .type = BOOT_ENTRY_UNIFIED,
        };
        _cleanup_fclose_ FILE *f = NULL;
        const char *k;
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
                           "ID", &os_id,
                           "VERSION_ID", &version_id,
                           "BUILD_ID", &build_id);
        if (r < 0)
                return log_error_errno(r, "Failed to parse os-release data from unified kernel image %s: %m", path);

        if (!os_pretty_name || !os_id || !(version_id || build_id))
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Missing fields in os-release data from unified kernel image %s, refusing.", path);

        tmp.id = strjoin(os_id, "-", version_id ?: build_id);
        if (!tmp.id)
                return log_oom();

        if (!efi_loader_entry_name_valid(tmp.id))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid loader entry: %s", tmp.id);

        tmp.path = strdup(path);
        if (!tmp.path)
                return log_oom();

        tmp.root = strdup(root);
        if (!tmp.root)
                return log_oom();

        tmp.kernel = strdup(skip_leading_chars(k, "/"));
        if (!tmp.kernel)
                return log_oom();

        tmp.options = strv_new(skip_leading_chars(cmdline, WHITESPACE));
        if (!tmp.options)
                return log_oom();

        delete_trailing_chars(tmp.options[0], WHITESPACE);

        tmp.title = TAKE_PTR(os_pretty_name);

        *ret = tmp;
        tmp = (BootEntry) {};
        return 0;
}

/* Maximum PE section we are willing to load (Note that sections we are not interested in may be larger, but
 * the ones we do care about and we are willing to load into memory have this size limit.) */
#define PE_SECTION_SIZE_MAX (4U*1024U*1024U)

static int find_sections(
                int fd,
                char **ret_osrelease,
                char **ret_cmdline) {

        _cleanup_free_ struct PeSectionHeader *sections = NULL;
        _cleanup_free_ char *osrelease = NULL, *cmdline = NULL;
        size_t i, n_sections;
        struct DosFileHeader dos;
        struct PeHeader pe;
        uint64_t start;
        ssize_t n;

        n = pread(fd, &dos, sizeof(dos), 0);
        if (n < 0)
                return log_error_errno(errno, "Failed read DOS header: %m");
        if (n != sizeof(dos))
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Short read while reading DOS header, refusing.");

        if (dos.Magic[0] != 'M' || dos.Magic[1] != 'Z')
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "DOS executable magic missing, refusing.");

        start = unaligned_read_le32(&dos.ExeHeader);
        n = pread(fd, &pe, sizeof(pe), start);
        if (n < 0)
                return log_error_errno(errno, "Failed to read PE header: %m");
        if (n != sizeof(pe))
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Short read while reading PE header, refusing.");

        if (pe.Magic[0] != 'P' || pe.Magic[1] != 'E' || pe.Magic[2] != 0 || pe.Magic[3] != 0)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "PE executable magic missing, refusing.");

        n_sections = unaligned_read_le16(&pe.FileHeader.NumberOfSections);
        if (n_sections > 96)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "PE header has too many sections, refusing.");

        sections = new(struct PeSectionHeader, n_sections);
        if (!sections)
                return log_oom();

        n = pread(fd, sections,
                  n_sections * sizeof(struct PeSectionHeader),
                  start + sizeof(pe) + unaligned_read_le16(&pe.FileHeader.SizeOfOptionalHeader));
        if (n < 0)
                return log_error_errno(errno, "Failed to read section data: %m");
        if ((size_t) n != n_sections * sizeof(struct PeSectionHeader))
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Short read while reading sections, refusing.");

        for (i = 0; i < n_sections; i++) {
                _cleanup_free_ char *k = NULL;
                uint32_t offset, size;
                char **b;

                if (strneq((char*) sections[i].Name, ".osrel", sizeof(sections[i].Name)))
                        b = &osrelease;
                else if (strneq((char*) sections[i].Name, ".cmdline", sizeof(sections[i].Name)))
                        b = &cmdline;
                else
                        continue;

                if (*b)
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Duplicate section %s, refusing.", sections[i].Name);

                offset = unaligned_read_le32(&sections[i].PointerToRawData);
                size = unaligned_read_le32(&sections[i].VirtualSize);

                if (size > PE_SECTION_SIZE_MAX)
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Section %s too large, refusing.", sections[i].Name);

                k = new(char, size+1);
                if (!k)
                        return log_oom();

                n = pread(fd, k, size, offset);
                if (n < 0)
                        return log_error_errno(errno, "Failed to read section payload: %m");
                if ((size_t) n != size)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Short read while reading section payload, refusing:");

                /* Allow one trailing NUL byte, but nothing more. */
                if (size > 0 && memchr(k, 0, size - 1))
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Section contains embedded NUL byte: %m");

                k[size] = 0;
                *b = TAKE_PTR(k);
        }

        if (!osrelease)
                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Image lacks .osrel section, refusing.");

        if (ret_osrelease)
                *ret_osrelease = TAKE_PTR(osrelease);
        if (ret_cmdline)
                *ret_cmdline = TAKE_PTR(cmdline);

        return 0;
}

static int boot_entries_find_unified(
                const char *root,
                const char *dir,
                BootEntry **entries,
                size_t *n_entries) {

        _cleanup_(closedirp) DIR *d = NULL;
        size_t n_allocated = *n_entries;
        struct dirent *de;
        int r;

        assert(root);
        assert(dir);
        assert(entries);
        assert(n_entries);

        d = opendir(dir);
        if (!d) {
                if (errno == ENOENT)
                        return 0;

                return log_error_errno(errno, "Failed to open %s: %m", dir);
        }

        FOREACH_DIRENT(de, d, return log_error_errno(errno, "Failed to read %s: %m", dir)) {
                _cleanup_free_ char *j = NULL, *osrelease = NULL, *cmdline = NULL;
                _cleanup_close_ int fd = -1;

                if (!dirent_is_file(de))
                        continue;

                if (!endswith_no_case(de->d_name, ".efi"))
                        continue;

                if (!GREEDY_REALLOC0(*entries, n_allocated, *n_entries + 1))
                        return log_oom();

                fd = openat(dirfd(d), de->d_name, O_RDONLY|O_CLOEXEC|O_NONBLOCK);
                if (fd < 0) {
                        log_warning_errno(errno, "Failed to open %s/%s, ignoring: %m", dir, de->d_name);
                        continue;
                }

                r = fd_verify_regular(fd);
                if (r < 0) {
                        log_warning_errno(r, "File %s/%s is not regular, ignoring: %m", dir, de->d_name);
                        continue;
                }

                r = find_sections(fd, &osrelease, &cmdline);
                if (r < 0)
                        continue;

                j = path_join(dir, de->d_name);
                if (!j)
                        return log_oom();

                r = boot_entry_load_unified(root, j, osrelease, cmdline, *entries + *n_entries);
                if (r < 0)
                        continue;

                (*n_entries) ++;
        }

        return 0;
}

static bool find_nonunique(BootEntry *entries, size_t n_entries, bool *arr) {
        size_t i, j;
        bool non_unique = false;

        assert(entries || n_entries == 0);
        assert(arr || n_entries == 0);

        for (i = 0; i < n_entries; i++)
                arr[i] = false;

        for (i = 0; i < n_entries; i++)
                for (j = 0; j < n_entries; j++)
                        if (i != j && streq(boot_entry_title(entries + i),
                                            boot_entry_title(entries + j)))
                                non_unique = arr[i] = arr[j] = true;

        return non_unique;
}

static int boot_entries_uniquify(BootEntry *entries, size_t n_entries) {
        char *s;
        size_t i;
        int r;
        bool arr[n_entries];

        assert(entries || n_entries == 0);

        /* Find _all_ non-unique titles */
        if (!find_nonunique(entries, n_entries, arr))
                return 0;

        /* Add version to non-unique titles */
        for (i = 0; i < n_entries; i++)
                if (arr[i] && entries[i].version) {
                        r = asprintf(&s, "%s (%s)", boot_entry_title(entries + i), entries[i].version);
                        if (r < 0)
                                return -ENOMEM;

                        free_and_replace(entries[i].show_title, s);
                }

        if (!find_nonunique(entries, n_entries, arr))
                return 0;

        /* Add machine-id to non-unique titles */
        for (i = 0; i < n_entries; i++)
                if (arr[i] && entries[i].machine_id) {
                        r = asprintf(&s, "%s (%s)", boot_entry_title(entries + i), entries[i].machine_id);
                        if (r < 0)
                                return -ENOMEM;

                        free_and_replace(entries[i].show_title, s);
                }

        if (!find_nonunique(entries, n_entries, arr))
                return 0;

        /* Add file name to non-unique titles */
        for (i = 0; i < n_entries; i++)
                if (arr[i]) {
                        r = asprintf(&s, "%s (%s)", boot_entry_title(entries + i), entries[i].id);
                        if (r < 0)
                                return -ENOMEM;

                        free_and_replace(entries[i].show_title, s);
                }

        return 0;
}

static int boot_entries_select_default(const BootConfig *config) {
        int i;

        assert(config);
        assert(config->entries || config->n_entries == 0);

        if (config->n_entries == 0) {
                log_debug("Found no default boot entry :(");
                return -1; /* -1 means "no default" */
        }

        if (config->entry_oneshot)
                for (i = config->n_entries - 1; i >= 0; i--)
                        if (streq(config->entry_oneshot, config->entries[i].id)) {
                                log_debug("Found default: id \"%s\" is matched by LoaderEntryOneShot",
                                          config->entries[i].id);
                                return i;
                        }

        if (config->entry_default)
                for (i = config->n_entries - 1; i >= 0; i--)
                        if (streq(config->entry_default, config->entries[i].id)) {
                                log_debug("Found default: id \"%s\" is matched by LoaderEntryDefault",
                                          config->entries[i].id);
                                return i;
                        }

        if (config->default_pattern)
                for (i = config->n_entries - 1; i >= 0; i--)
                        if (fnmatch(config->default_pattern, config->entries[i].id, FNM_CASEFOLD) == 0) {
                                log_debug("Found default: id \"%s\" is matched by pattern \"%s\"",
                                          config->entries[i].id, config->default_pattern);
                                return i;
                        }

        log_debug("Found default: last entry \"%s\"", config->entries[config->n_entries - 1].id);
        return config->n_entries - 1;
}

int boot_entries_load_config(
                const char *esp_path,
                const char *xbootldr_path,
                BootConfig *config) {

        const char *p;
        int r;

        assert(config);

        if (esp_path) {
                p = strjoina(esp_path, "/loader/loader.conf");
                r = boot_loader_read_conf(p, config);
                if (r < 0)
                        return r;

                p = strjoina(esp_path, "/loader/entries");
                r = boot_entries_find(esp_path, p, &config->entries, &config->n_entries);
                if (r < 0)
                        return r;

                p = strjoina(esp_path, "/EFI/Linux/");
                r = boot_entries_find_unified(esp_path, p, &config->entries, &config->n_entries);
                if (r < 0)
                        return r;
        }

        if (xbootldr_path) {
                p = strjoina(xbootldr_path, "/loader/entries");
                r = boot_entries_find(xbootldr_path, p, &config->entries, &config->n_entries);
                if (r < 0)
                        return r;

                p = strjoina(xbootldr_path, "/EFI/Linux/");
                r = boot_entries_find_unified(xbootldr_path, p, &config->entries, &config->n_entries);
                if (r < 0)
                        return r;
        }

        typesafe_qsort(config->entries, config->n_entries, boot_entry_compare);

        r = boot_entries_uniquify(config->entries, config->n_entries);
        if (r < 0)
                return log_error_errno(r, "Failed to uniquify boot entries: %m");

        if (is_efi_boot()) {
                r = efi_get_variable_string(EFI_VENDOR_LOADER, "LoaderEntryOneShot", &config->entry_oneshot);
                if (r < 0 && !IN_SET(r, -ENOENT, -ENODATA)) {
                        log_warning_errno(r, "Failed to read EFI variable \"LoaderEntryOneShot\": %m");
                        if (r == -ENOMEM)
                                return r;
                }

                r = efi_get_variable_string(EFI_VENDOR_LOADER, "LoaderEntryDefault", &config->entry_default);
                if (r < 0 && !IN_SET(r, -ENOENT, -ENODATA)) {
                        log_warning_errno(r, "Failed to read EFI variable \"LoaderEntryDefault\": %m");
                        if (r == -ENOMEM)
                                return r;
                }
        }

        config->default_entry = boot_entries_select_default(config);
        return 0;
}

int boot_entries_load_config_auto(
                const char *override_esp_path,
                const char *override_xbootldr_path,
                BootConfig *config) {

        _cleanup_free_ char *esp_where = NULL, *xbootldr_where = NULL;
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
                        return boot_entries_load_config("/run/boot-loader-entries/", NULL, config);

                if (errno != ENOENT)
                        return log_error_errno(errno,
                                               "Failed to determine whether /run/boot-loader-entries/ exists: %m");
        }

        r = find_esp_and_warn(override_esp_path, false, &esp_where, NULL, NULL, NULL, NULL);
        if (r < 0) /* we don't log about ENOKEY here, but propagate it, leaving it to the caller to log */
                return r;

        r = find_xbootldr_and_warn(override_xbootldr_path, false, &xbootldr_where, NULL);
        if (r < 0 && r != -ENOKEY)
                return r; /* It's fine if the XBOOTLDR partition doesn't exist, hence we ignore ENOKEY here */

        return boot_entries_load_config(esp_where, xbootldr_where, config);
}

#if ENABLE_EFI
int boot_entries_augment_from_loader(BootConfig *config, bool only_auto) {
        static const char * const title_table[] = {
                /* Pretty names for a few well-known automatically discovered entries. */
                "auto-osx",                      "macOS",
                "auto-windows",                  "Windows Boot Manager",
                "auto-efi-shell",                "EFI Shell",
                "auto-efi-default",              "EFI Default Loader",
                "auto-reboot-to-firmware-setup", "Reboot Into Firmware Interface",
        };

        _cleanup_strv_free_ char **found_by_loader = NULL;
        size_t n_allocated;
        char **i;
        int r;

        assert(config);

        /* Let's add the entries discovered by the boot loader to the end of our list, unless they are
         * already included there. */

        r = efi_loader_get_entries(&found_by_loader);
        if (IN_SET(r, -ENOENT, -EOPNOTSUPP))
                return log_debug_errno(r, "Boot loader reported no entries.");
        if (r < 0)
                return log_error_errno(r, "Failed to determine entries reported by boot loader: %m");

        n_allocated = config->n_entries;

        STRV_FOREACH(i, found_by_loader) {
                _cleanup_free_ char *c = NULL, *t = NULL, *p = NULL;
                char **a, **b;

                if (boot_config_has_entry(config, *i))
                        continue;

                if (only_auto && !startswith(*i, "auto-"))
                        continue;

                c = strdup(*i);
                if (!c)
                        return log_oom();

                STRV_FOREACH_PAIR(a, b, (char**) title_table)
                        if (streq(*a, *i)) {
                                t = strdup(*b);
                                if (!t)
                                        return log_oom();
                                break;
                        }

                p = efi_variable_path(EFI_VENDOR_LOADER, "LoaderEntries");
                if (!p)
                        return log_oom();

                if (!GREEDY_REALLOC0(config->entries, n_allocated, config->n_entries + 1))
                        return log_oom();

                config->entries[config->n_entries++] = (BootEntry) {
                        .type = BOOT_ENTRY_LOADER,
                        .id = TAKE_PTR(c),
                        .title = TAKE_PTR(t),
                        .path = TAKE_PTR(p),
                };
        }

        return 0;
}
#endif

/********************************************************************************/

static int verify_esp_blkid(
                dev_t devid,
                bool searching,
                uint32_t *ret_part,
                uint64_t *ret_pstart,
                uint64_t *ret_psize,
                sd_id128_t *ret_uuid) {

        sd_id128_t uuid = SD_ID128_NULL;
        uint64_t pstart = 0, psize = 0;
        uint32_t part = 0;

#if HAVE_BLKID
        _cleanup_(blkid_free_probep) blkid_probe b = NULL;
        _cleanup_free_ char *node = NULL;
        const char *v;
        int r;

        r = device_path_make_major_minor(S_IFBLK, devid, &node);
        if (r < 0)
                return log_error_errno(r, "Failed to format major/minor device path: %m");

        errno = 0;
        b = blkid_new_probe_from_filename(node);
        if (!b)
                return log_error_errno(errno ?: SYNTHETIC_ERRNO(ENOMEM), "Failed to open file system \"%s\": %m", node);

        blkid_probe_enable_superblocks(b, 1);
        blkid_probe_set_superblocks_flags(b, BLKID_SUBLKS_TYPE);
        blkid_probe_enable_partitions(b, 1);
        blkid_probe_set_partitions_flags(b, BLKID_PARTS_ENTRY_DETAILS);

        errno = 0;
        r = blkid_do_safeprobe(b);
        if (r == -2)
                return log_error_errno(SYNTHETIC_ERRNO(ENODEV), "File system \"%s\" is ambiguous.", node);
        else if (r == 1)
                return log_error_errno(SYNTHETIC_ERRNO(ENODEV), "File system \"%s\" does not contain a label.", node);
        else if (r != 0)
                return log_error_errno(errno ?: SYNTHETIC_ERRNO(EIO), "Failed to probe file system \"%s\": %m", node);

        errno = 0;
        r = blkid_probe_lookup_value(b, "TYPE", &v, NULL);
        if (r != 0)
                return log_error_errno(errno ?: SYNTHETIC_ERRNO(EIO), "Failed to probe file system type of \"%s\": %m", node);
        if (!streq(v, "vfat"))
                return log_full_errno(searching ? LOG_DEBUG : LOG_ERR,
                                      SYNTHETIC_ERRNO(searching ? EADDRNOTAVAIL : ENODEV),
                                      "File system \"%s\" is not FAT.", node);

        errno = 0;
        r = blkid_probe_lookup_value(b, "PART_ENTRY_SCHEME", &v, NULL);
        if (r != 0)
                return log_error_errno(errno ?: SYNTHETIC_ERRNO(EIO), "Failed to probe partition scheme of \"%s\": %m", node);
        if (!streq(v, "gpt"))
                return log_full_errno(searching ? LOG_DEBUG : LOG_ERR,
                                      SYNTHETIC_ERRNO(searching ? EADDRNOTAVAIL : ENODEV),
                                      "File system \"%s\" is not on a GPT partition table.", node);

        errno = 0;
        r = blkid_probe_lookup_value(b, "PART_ENTRY_TYPE", &v, NULL);
        if (r != 0)
                return log_error_errno(errno ?: EIO, "Failed to probe partition type UUID of \"%s\": %m", node);
        if (!streq(v, "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"))
                return log_full_errno(searching ? LOG_DEBUG : LOG_ERR,
                                       SYNTHETIC_ERRNO(searching ? EADDRNOTAVAIL : ENODEV),
                                       "File system \"%s\" has wrong type for an EFI System Partition (ESP).", node);

        errno = 0;
        r = blkid_probe_lookup_value(b, "PART_ENTRY_UUID", &v, NULL);
        if (r != 0)
                return log_error_errno(errno ?: SYNTHETIC_ERRNO(EIO), "Failed to probe partition entry UUID of \"%s\": %m", node);
        r = sd_id128_from_string(v, &uuid);
        if (r < 0)
                return log_error_errno(r, "Partition \"%s\" has invalid UUID \"%s\".", node, v);

        errno = 0;
        r = blkid_probe_lookup_value(b, "PART_ENTRY_NUMBER", &v, NULL);
        if (r != 0)
                return log_error_errno(errno ?: SYNTHETIC_ERRNO(EIO), "Failed to probe partition number of \"%s\": m", node);
        r = safe_atou32(v, &part);
        if (r < 0)
                return log_error_errno(r, "Failed to parse PART_ENTRY_NUMBER field.");

        errno = 0;
        r = blkid_probe_lookup_value(b, "PART_ENTRY_OFFSET", &v, NULL);
        if (r != 0)
                return log_error_errno(errno ?: SYNTHETIC_ERRNO(EIO), "Failed to probe partition offset of \"%s\": %m", node);
        r = safe_atou64(v, &pstart);
        if (r < 0)
                return log_error_errno(r, "Failed to parse PART_ENTRY_OFFSET field.");

        errno = 0;
        r = blkid_probe_lookup_value(b, "PART_ENTRY_SIZE", &v, NULL);
        if (r != 0)
                return log_error_errno(errno ?: SYNTHETIC_ERRNO(EIO), "Failed to probe partition size of \"%s\": %m", node);
        r = safe_atou64(v, &psize);
        if (r < 0)
                return log_error_errno(r, "Failed to parse PART_ENTRY_SIZE field.");
#endif

        if (ret_part)
                *ret_part = part;
        if (ret_pstart)
                *ret_pstart = pstart;
        if (ret_psize)
                *ret_psize = psize;
        if (ret_uuid)
                *ret_uuid = uuid;

        return 0;
}

static int verify_esp_udev(
                dev_t devid,
                bool searching,
                uint32_t *ret_part,
                uint64_t *ret_pstart,
                uint64_t *ret_psize,
                sd_id128_t *ret_uuid) {

        _cleanup_(sd_device_unrefp) sd_device *d = NULL;
        _cleanup_free_ char *node = NULL;
        sd_id128_t uuid = SD_ID128_NULL;
        uint64_t pstart = 0, psize = 0;
        uint32_t part = 0;
        const char *v;
        int r;

        r = device_path_make_major_minor(S_IFBLK, devid, &node);
        if (r < 0)
                return log_error_errno(r, "Failed to format major/minor device path: %m");

        r = sd_device_new_from_devnum(&d, 'b', devid);
        if (r < 0)
                return log_error_errno(r, "Failed to get device from device number: %m");

        r = sd_device_get_property_value(d, "ID_FS_TYPE", &v);
        if (r < 0)
                return log_error_errno(r, "Failed to get device property: %m");
        if (!streq(v, "vfat"))
                return log_full_errno(searching ? LOG_DEBUG : LOG_ERR,
                                      SYNTHETIC_ERRNO(searching ? EADDRNOTAVAIL : ENODEV),
                                      "File system \"%s\" is not FAT.", node );

        r = sd_device_get_property_value(d, "ID_PART_ENTRY_SCHEME", &v);
        if (r < 0)
                return log_error_errno(r, "Failed to get device property: %m");
        if (!streq(v, "gpt"))
                return log_full_errno(searching ? LOG_DEBUG : LOG_ERR,
                                      SYNTHETIC_ERRNO(searching ? EADDRNOTAVAIL : ENODEV),
                                      "File system \"%s\" is not on a GPT partition table.", node);

        r = sd_device_get_property_value(d, "ID_PART_ENTRY_TYPE", &v);
        if (r < 0)
                return log_error_errno(r, "Failed to get device property: %m");
        if (!streq(v, "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"))
                return log_full_errno(searching ? LOG_DEBUG : LOG_ERR,
                                       SYNTHETIC_ERRNO(searching ? EADDRNOTAVAIL : ENODEV),
                                       "File system \"%s\" has wrong type for an EFI System Partition (ESP).", node);

        r = sd_device_get_property_value(d, "ID_PART_ENTRY_UUID", &v);
        if (r < 0)
                return log_error_errno(r, "Failed to get device property: %m");
        r = sd_id128_from_string(v, &uuid);
        if (r < 0)
                return log_error_errno(r, "Partition \"%s\" has invalid UUID \"%s\".", node, v);

        r = sd_device_get_property_value(d, "ID_PART_ENTRY_NUMBER", &v);
        if (r < 0)
                return log_error_errno(r, "Failed to get device property: %m");
        r = safe_atou32(v, &part);
        if (r < 0)
                return log_error_errno(r, "Failed to parse PART_ENTRY_NUMBER field.");

        r = sd_device_get_property_value(d, "ID_PART_ENTRY_OFFSET", &v);
        if (r < 0)
                return log_error_errno(r, "Failed to get device property: %m");
        r = safe_atou64(v, &pstart);
        if (r < 0)
                return log_error_errno(r, "Failed to parse PART_ENTRY_OFFSET field.");

        r = sd_device_get_property_value(d, "ID_PART_ENTRY_SIZE", &v);
        if (r < 0)
                return log_error_errno(r, "Failed to get device property: %m");
        r = safe_atou64(v, &psize);
        if (r < 0)
                return log_error_errno(r, "Failed to parse PART_ENTRY_SIZE field.");

        if (ret_part)
                *ret_part = part;
        if (ret_pstart)
                *ret_pstart = pstart;
        if (ret_psize)
                *ret_psize = psize;
        if (ret_uuid)
                *ret_uuid = uuid;

        return 0;
}

static int verify_fsroot_dir(
                const char *path,
                bool searching,
                bool unprivileged_mode,
                dev_t *ret_dev) {

        struct stat st, st2;
        const char *t2, *trigger;
        int r;

        assert(path);
        assert(ret_dev);

        /* So, the ESP and XBOOTLDR partition are commonly located on an autofs mount. stat() on the
         * directory won't trigger it, if it is not mounted yet. Let's hence explicitly trigger it here,
         * before stat()ing */
        trigger = strjoina(path, "/trigger"); /* Filename doesn't matter... */
        (void) access(trigger, F_OK);

        if (stat(path, &st) < 0)
                return log_full_errno((searching && errno == ENOENT) ||
                                      (unprivileged_mode && errno == EACCES) ? LOG_DEBUG : LOG_ERR, errno,
                                      "Failed to determine block device node of \"%s\": %m", path);

        if (major(st.st_dev) == 0)
                return log_full_errno(searching ? LOG_DEBUG : LOG_ERR,
                                      SYNTHETIC_ERRNO(searching ? EADDRNOTAVAIL : ENODEV),
                                      "Block device node of \"%s\" is invalid.", path);

        t2 = strjoina(path, "/..");
        if (stat(t2, &st2) < 0) {
                if (errno != EACCES)
                        r = -errno;
                else {
                        _cleanup_free_ char *parent = NULL;

                        /* If going via ".." didn't work due to EACCESS, then let's determine the parent path
                         * directly instead. It's not as good, due to symlinks and such, but we can't do
                         * anything better here. */

                        parent = dirname_malloc(path);
                        if (!parent)
                                return log_oom();

                        if (stat(parent, &st2) < 0)
                                r = -errno;
                        else
                                r = 0;
                }

                if (r < 0)
                        return log_full_errno(unprivileged_mode && r == -EACCES ? LOG_DEBUG : LOG_ERR, r,
                                              "Failed to determine block device node of parent of \"%s\": %m", path);
        }

        if (st.st_dev == st2.st_dev)
                return log_full_errno(searching ? LOG_DEBUG : LOG_ERR,
                                      SYNTHETIC_ERRNO(searching ? EADDRNOTAVAIL : ENODEV),
                                      "Directory \"%s\" is not the root of the file system.", path);

        if (ret_dev)
                *ret_dev = st.st_dev;

        return 0;
}

static int verify_esp(
                const char *p,
                bool searching,
                bool unprivileged_mode,
                uint32_t *ret_part,
                uint64_t *ret_pstart,
                uint64_t *ret_psize,
                sd_id128_t *ret_uuid) {

        bool relax_checks;
        dev_t devid;
        int r;

        assert(p);

        /* This logs about all errors, except:
         *
         *  -ENOENT        → if 'searching' is set, and the dir doesn't exist
         *  -EADDRNOTAVAIL → if 'searching' is set, and the dir doesn't look like an ESP
         *  -EACESS        → if 'unprivileged_mode' is set, and we have trouble accessing the thing
         */

        relax_checks = getenv_bool("SYSTEMD_RELAX_ESP_CHECKS") > 0;

        /* Non-root user can only check the status, so if an error occurred in the following, it does not cause any
         * issues. Let's also, silence the error messages. */

        if (!relax_checks) {
                struct statfs sfs;

                if (statfs(p, &sfs) < 0)
                        /* If we are searching for the mount point, don't generate a log message if we can't find the path */
                        return log_full_errno((searching && errno == ENOENT) ||
                                              (unprivileged_mode && errno == EACCES) ? LOG_DEBUG : LOG_ERR, errno,
                                              "Failed to check file system type of \"%s\": %m", p);

                if (!F_TYPE_EQUAL(sfs.f_type, MSDOS_SUPER_MAGIC))
                        return log_full_errno(searching ? LOG_DEBUG : LOG_ERR,
                                              SYNTHETIC_ERRNO(searching ? EADDRNOTAVAIL : ENODEV),
                                              "File system \"%s\" is not a FAT EFI System Partition (ESP) file system.", p);
        }

        r = verify_fsroot_dir(p, searching, unprivileged_mode, &devid);
        if (r < 0)
                return r;

        /* In a container we don't have access to block devices, skip this part of the verification, we trust
         * the container manager set everything up correctly on its own. */
        if (detect_container() > 0 || relax_checks)
                goto finish;

        /* If we are unprivileged we ask udev for the metadata about the partition. If we are privileged we
         * use blkid instead. Why? Because this code is called from 'bootctl' which is pretty much an
         * emergency recovery tool that should also work when udev isn't up (i.e. from the emergency shell),
         * however blkid can't work if we have no privileges to access block devices directly, which is why
         * we use udev in that case. */
        if (unprivileged_mode)
                return verify_esp_udev(devid, searching, ret_part, ret_pstart, ret_psize, ret_uuid);
        else
                return verify_esp_blkid(devid, searching, ret_part, ret_pstart, ret_psize, ret_uuid);

finish:
        if (ret_part)
                *ret_part = 0;
        if (ret_pstart)
                *ret_pstart = 0;
        if (ret_psize)
                *ret_psize = 0;
        if (ret_uuid)
                *ret_uuid = SD_ID128_NULL;

        return 0;
}

int find_esp_and_warn(
                const char *path,
                bool unprivileged_mode,
                char **ret_path,
                uint32_t *ret_part,
                uint64_t *ret_pstart,
                uint64_t *ret_psize,
                sd_id128_t *ret_uuid) {

        int r;

        /* This logs about all errors except:
         *
         *    -ENOKEY → when we can't find the partition
         *   -EACCESS → when unprivileged_mode is true, and we can't access something
         */

        if (path) {
                r = verify_esp(path, false, unprivileged_mode, ret_part, ret_pstart, ret_psize, ret_uuid);
                if (r < 0)
                        return r;

                goto found;
        }

        path = getenv("SYSTEMD_ESP_PATH");
        if (path) {
                if (!path_is_valid(path) || !path_is_absolute(path))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "$SYSTEMD_ESP_PATH does not refer to absolute path, refusing to use it: %s",
                                               path);

                /* Note: when the user explicitly configured things with an env var we won't validate the mount
                 * point. After all we want this to be useful for testing. */
                goto found;
        }

        FOREACH_STRING(path, "/efi", "/boot", "/boot/efi") {

                r = verify_esp(path, true, unprivileged_mode, ret_part, ret_pstart, ret_psize, ret_uuid);
                if (r >= 0)
                        goto found;
                if (!IN_SET(r, -ENOENT, -EADDRNOTAVAIL)) /* This one is not it */
                        return r;
        }

        /* No logging here */
        return -ENOKEY;

found:
        if (ret_path) {
                char *c;

                c = strdup(path);
                if (!c)
                        return log_oom();

                *ret_path = c;
        }

        return 0;
}

static int verify_xbootldr_blkid(
                dev_t devid,
                bool searching,
                sd_id128_t *ret_uuid) {

        sd_id128_t uuid = SD_ID128_NULL;

#if HAVE_BLKID
        _cleanup_(blkid_free_probep) blkid_probe b = NULL;
        _cleanup_free_ char *node = NULL;
        const char *v;
        int r;

        r = device_path_make_major_minor(S_IFBLK, devid, &node);
        if (r < 0)
                return log_error_errno(r, "Failed to format major/minor device path: %m");
        errno = 0;
        b = blkid_new_probe_from_filename(node);
        if (!b)
                return log_error_errno(errno ?: SYNTHETIC_ERRNO(ENOMEM), "Failed to open file system \"%s\": %m", node);

        blkid_probe_enable_partitions(b, 1);
        blkid_probe_set_partitions_flags(b, BLKID_PARTS_ENTRY_DETAILS);

        errno = 0;
        r = blkid_do_safeprobe(b);
        if (r == -2)
                return log_error_errno(SYNTHETIC_ERRNO(ENODEV), "File system \"%s\" is ambiguous.", node);
        else if (r == 1)
                return log_error_errno(SYNTHETIC_ERRNO(ENODEV), "File system \"%s\" does not contain a label.", node);
        else if (r != 0)
                return log_error_errno(errno ?: SYNTHETIC_ERRNO(EIO), "Failed to probe file system \"%s\": %m", node);

        errno = 0;
        r = blkid_probe_lookup_value(b, "PART_ENTRY_SCHEME", &v, NULL);
        if (r != 0)
                return log_error_errno(errno ?: SYNTHETIC_ERRNO(EIO), "Failed to probe partition scheme of \"%s\": %m", node);
        if (streq(v, "gpt")) {

                errno = 0;
                r = blkid_probe_lookup_value(b, "PART_ENTRY_TYPE", &v, NULL);
                if (r != 0)
                        return log_error_errno(errno ?: SYNTHETIC_ERRNO(EIO), "Failed to probe partition type UUID of \"%s\": %m", node);
                if (!streq(v, "bc13c2ff-59e6-4262-a352-b275fd6f7172"))
                        return log_full_errno(searching ? LOG_DEBUG : LOG_ERR,
                                              searching ? SYNTHETIC_ERRNO(EADDRNOTAVAIL) : SYNTHETIC_ERRNO(ENODEV),
                                              "File system \"%s\" has wrong type for extended boot loader partition.", node);

                errno = 0;
                r = blkid_probe_lookup_value(b, "PART_ENTRY_UUID", &v, NULL);
                if (r != 0)
                        return log_error_errno(errno ?: SYNTHETIC_ERRNO(EIO), "Failed to probe partition entry UUID of \"%s\": %m", node);
                r = sd_id128_from_string(v, &uuid);
                if (r < 0)
                        return log_error_errno(r, "Partition \"%s\" has invalid UUID \"%s\".", node, v);

        } else if (streq(v, "dos")) {

                errno = 0;
                r = blkid_probe_lookup_value(b, "PART_ENTRY_TYPE", &v, NULL);
                if (r != 0)
                        return log_error_errno(errno ?: SYNTHETIC_ERRNO(EIO), "Failed to probe partition type UUID of \"%s\": %m", node);
                if (!streq(v, "0xea"))
                        return log_full_errno(searching ? LOG_DEBUG : LOG_ERR,
                                              searching ? SYNTHETIC_ERRNO(EADDRNOTAVAIL) : SYNTHETIC_ERRNO(ENODEV),
                                              "File system \"%s\" has wrong type for extended boot loader partition.", node);

        } else
                return log_full_errno(searching ? LOG_DEBUG : LOG_ERR,
                                      searching ? SYNTHETIC_ERRNO(EADDRNOTAVAIL) : SYNTHETIC_ERRNO(ENODEV),
                                      "File system \"%s\" is not on a GPT or DOS partition table.", node);
#endif

        if (ret_uuid)
                *ret_uuid = uuid;

        return 0;
}

static int verify_xbootldr_udev(
                dev_t devid,
                bool searching,
                sd_id128_t *ret_uuid) {

        _cleanup_(sd_device_unrefp) sd_device *d = NULL;
        _cleanup_free_ char *node = NULL;
        sd_id128_t uuid = SD_ID128_NULL;
        const char *v;
        int r;

        r = device_path_make_major_minor(S_IFBLK, devid, &node);
        if (r < 0)
                return log_error_errno(r, "Failed to format major/minor device path: %m");

        r = sd_device_new_from_devnum(&d, 'b', devid);
        if (r < 0)
                return log_error_errno(r, "Failed to get device from device number: %m");

        r = sd_device_get_property_value(d, "ID_PART_ENTRY_SCHEME", &v);
        if (r < 0)
                return log_error_errno(r, "Failed to get device property: %m");

        if (streq(v, "gpt")) {

                r = sd_device_get_property_value(d, "ID_PART_ENTRY_TYPE", &v);
                if (r < 0)
                        return log_error_errno(r, "Failed to get device property: %m");
                if (!streq(v, "bc13c2ff-59e6-4262-a352-b275fd6f7172"))
                        return log_full_errno(searching ? LOG_DEBUG : LOG_ERR,
                                              searching ? SYNTHETIC_ERRNO(EADDRNOTAVAIL) : SYNTHETIC_ERRNO(ENODEV),
                                              "File system \"%s\" has wrong type for extended boot loader partition.", node);

                r = sd_device_get_property_value(d, "ID_PART_ENTRY_UUID", &v);
                if (r < 0)
                        return log_error_errno(r, "Failed to get device property: %m");
                r = sd_id128_from_string(v, &uuid);
                if (r < 0)
                        return log_error_errno(r, "Partition \"%s\" has invalid UUID \"%s\".", node, v);

        } else if (streq(v, "dos")) {

                r = sd_device_get_property_value(d, "ID_PART_ENTRY_TYPE", &v);
                if (r < 0)
                        return log_error_errno(r, "Failed to get device property: %m");
                if (!streq(v, "0xea"))
                        return log_full_errno(searching ? LOG_DEBUG : LOG_ERR,
                                              searching ? SYNTHETIC_ERRNO(EADDRNOTAVAIL) : SYNTHETIC_ERRNO(ENODEV),
                                              "File system \"%s\" has wrong type for extended boot loader partition.", node);
        } else
                return log_full_errno(searching ? LOG_DEBUG : LOG_ERR,
                                      searching ? SYNTHETIC_ERRNO(EADDRNOTAVAIL) : SYNTHETIC_ERRNO(ENODEV),
                                      "File system \"%s\" is not on a GPT or DOS partition table.", node);

        if (ret_uuid)
                *ret_uuid = uuid;

        return 0;
}

static int verify_xbootldr(
                const char *p,
                bool searching,
                bool unprivileged_mode,
                sd_id128_t *ret_uuid) {

        bool relax_checks;
        dev_t devid;
        int r;

        assert(p);

        relax_checks = getenv_bool("SYSTEMD_RELAX_XBOOTLDR_CHECKS") > 0;

        r = verify_fsroot_dir(p, searching, unprivileged_mode, &devid);
        if (r < 0)
                return r;

        if (detect_container() > 0 || relax_checks)
                goto finish;

        if (unprivileged_mode)
                return verify_xbootldr_udev(devid, searching, ret_uuid);
        else
                return verify_xbootldr_blkid(devid, searching, ret_uuid);

finish:
        if (ret_uuid)
                *ret_uuid = SD_ID128_NULL;

        return 0;
}

int find_xbootldr_and_warn(
                const char *path,
                bool unprivileged_mode,
                char **ret_path,
                sd_id128_t *ret_uuid) {

        int r;

        /* Similar to find_esp_and_warn(), but finds the XBOOTLDR partition. Returns the same errors. */

        if (path) {
                r = verify_xbootldr(path, false, unprivileged_mode, ret_uuid);
                if (r < 0)
                        return r;

                goto found;
        }

        path = getenv("SYSTEMD_XBOOTLDR_PATH");
        if (path) {
                if (!path_is_valid(path) || !path_is_absolute(path))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "$SYSTEMD_XBOOTLDR_PATH does not refer to absolute path, refusing to use it: %s",
                                               path);

                goto found;
        }

        r = verify_xbootldr("/boot", true, unprivileged_mode, ret_uuid);
        if (r >= 0) {
                path = "/boot";
                goto found;
        }
        if (!IN_SET(r, -ENOENT, -EADDRNOTAVAIL)) /* This one is not it */
                return r;

        return -ENOKEY;

found:
        if (ret_path) {
                char *c;

                c = strdup(path);
                if (!c)
                        return log_oom();

                *ret_path = c;
        }

        return 0;
}
