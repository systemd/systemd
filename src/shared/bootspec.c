/* SPDX-License-Identifier: LGPL-2.1+ */

#include <stdio.h>
#include <linux/magic.h>

#include "sd-id128.h"

#include "alloc-util.h"
#include "blkid-util.h"
#include "bootspec.h"
#include "conf-files.h"
#include "def.h"
#include "device-nodes.h"
#include "efivars.h"
#include "env-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "parse-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "virt.h"

static void boot_entry_free(BootEntry *entry) {
        assert(entry);

        free(entry->id);
        free(entry->path);
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

static int boot_entry_load(const char *path, BootEntry *entry) {
        _cleanup_(boot_entry_free) BootEntry tmp = {};
        _cleanup_fclose_ FILE *f = NULL;
        unsigned line = 1;
        char *b, *c;
        int r;

        assert(path);
        assert(entry);

        c = endswith_no_case(path, ".conf");
        if (!c) {
                log_error("Invalid loader entry filename: %s", path);
                return -EINVAL;
        }

        b = basename(path);
        tmp.id = strndup(b, c - b);
        if (!tmp.id)
                return log_oom();

        tmp.path = strdup(path);
        if (!tmp.path)
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
                        log_notice("%s:%u: Unknown line \"%s\"", path, line, field);
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
                        log_notice("%s:%u: Unknown line \"%s\"", path, line, field);
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

static int boot_entries_find(const char *dir, BootEntry **ret_entries, size_t *ret_n_entries) {
        _cleanup_strv_free_ char **files = NULL;
        char **f;
        int r;
        BootEntry *array = NULL;
        size_t n_allocated = 0, n = 0;

        assert(dir);
        assert(ret_entries);
        assert(ret_n_entries);

        r = conf_files_list(&files, ".conf", NULL, 0, dir, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to list files in \"%s\": %m", dir);

        STRV_FOREACH(f, files) {
                if (!GREEDY_REALLOC0(array, n_allocated, n + 1))
                        return log_oom();

                r = boot_entry_load(*f, array + n);
                if (r < 0)
                        continue;

                n++;
        }

        typesafe_qsort(array, n, boot_entry_compare);

        *ret_entries = array;
        *ret_n_entries = n;

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

        if (config->n_entries > 0)
                log_debug("Found default: last entry \"%s\"", config->entries[config->n_entries - 1].id);
        else
                log_debug("Found no default boot entry :(");

        return config->n_entries - 1; /* -1 means "no default" */
}

int boot_entries_load_config(const char *esp_path, BootConfig *config) {
        const char *p;
        int r;

        assert(esp_path);
        assert(config);

        p = strjoina(esp_path, "/loader/loader.conf");
        r = boot_loader_read_conf(p, config);
        if (r < 0)
                return r;

        p = strjoina(esp_path, "/loader/entries");
        r = boot_entries_find(p, &config->entries, &config->n_entries);
        if (r < 0)
                return r;

        r = boot_entries_uniquify(config->entries, config->n_entries);
        if (r < 0)
                return log_error_errno(r, "Failed to uniquify boot entries: %m");

        if (is_efi_boot()) {
                r = efi_get_variable_string(EFI_VENDOR_LOADER, "LoaderEntryOneShot", &config->entry_oneshot);
                if (r < 0 && r != -ENOENT)
                        return log_error_errno(r, "Failed to read EFI var \"LoaderEntryOneShot\": %m");

                r = efi_get_variable_string(EFI_VENDOR_LOADER, "LoaderEntryDefault", &config->entry_default);
                if (r < 0 && r != -ENOENT)
                        return log_error_errno(r, "Failed to read EFI var \"LoaderEntryDefault\": %m");
        }

        config->default_entry = boot_entries_select_default(config);
        return 0;
}

/********************************************************************************/

static int verify_esp(
                const char *p,
                bool searching,
                bool unprivileged_mode,
                uint32_t *ret_part,
                uint64_t *ret_pstart,
                uint64_t *ret_psize,
                sd_id128_t *ret_uuid) {
#if HAVE_BLKID
        _cleanup_(blkid_free_probep) blkid_probe b = NULL;
        char t[DEV_NUM_PATH_MAX];
        const char *v;
#endif
        uint64_t pstart = 0, psize = 0;
        struct stat st, st2;
        const char *t2;
        struct statfs sfs;
        sd_id128_t uuid = SD_ID128_NULL;
        uint32_t part = 0;
        bool relax_checks;
        int r;

        assert(p);

        relax_checks = getenv_bool("SYSTEMD_RELAX_ESP_CHECKS") > 0;

        /* Non-root user can only check the status, so if an error occured in the following, it does not cause any
         * issues. Let's also, silence the error messages. */

        if (!relax_checks) {
                if (statfs(p, &sfs) < 0) {
                        /* If we are searching for the mount point, don't generate a log message if we can't find the path */
                        if (errno == ENOENT && searching)
                                return -ENOENT;

                        return log_full_errno(unprivileged_mode && errno == EACCES ? LOG_DEBUG : LOG_ERR, errno,
                                              "Failed to check file system type of \"%s\": %m", p);
                }

                if (!F_TYPE_EQUAL(sfs.f_type, MSDOS_SUPER_MAGIC)) {
                        if (searching)
                                return -EADDRNOTAVAIL;

                        log_error("File system \"%s\" is not a FAT EFI System Partition (ESP) file system.", p);
                        return -ENODEV;
                }
        }

        if (stat(p, &st) < 0)
                return log_full_errno(unprivileged_mode && errno == EACCES ? LOG_DEBUG : LOG_ERR, errno,
                                      "Failed to determine block device node of \"%s\": %m", p);

        if (major(st.st_dev) == 0) {
                log_error("Block device node of %p is invalid.", p);
                return -ENODEV;
        }

        t2 = strjoina(p, "/..");
        r = stat(t2, &st2);
        if (r < 0)
                return log_full_errno(unprivileged_mode && errno == EACCES ? LOG_DEBUG : LOG_ERR, errno,
                                      "Failed to determine block device node of parent of \"%s\": %m", p);

        if (st.st_dev == st2.st_dev) {
                log_error("Directory \"%s\" is not the root of the EFI System Partition (ESP) file system.", p);
                return -ENODEV;
        }

        /* In a container we don't have access to block devices, skip this part of the verification, we trust the
         * container manager set everything up correctly on its own. Also skip the following verification for non-root user. */
        if (detect_container() > 0 || unprivileged_mode || relax_checks)
                goto finish;

#if HAVE_BLKID
        xsprintf_dev_num_path(t, "block", st.st_dev);
        errno = 0;
        b = blkid_new_probe_from_filename(t);
        if (!b)
                return log_error_errno(errno ?: ENOMEM, "Failed to open file system \"%s\": %m", p);

        blkid_probe_enable_superblocks(b, 1);
        blkid_probe_set_superblocks_flags(b, BLKID_SUBLKS_TYPE);
        blkid_probe_enable_partitions(b, 1);
        blkid_probe_set_partitions_flags(b, BLKID_PARTS_ENTRY_DETAILS);

        errno = 0;
        r = blkid_do_safeprobe(b);
        if (r == -2) {
                log_error("File system \"%s\" is ambiguous.", p);
                return -ENODEV;
        } else if (r == 1) {
                log_error("File system \"%s\" does not contain a label.", p);
                return -ENODEV;
        } else if (r != 0)
                return log_error_errno(errno ?: EIO, "Failed to probe file system \"%s\": %m", p);

        errno = 0;
        r = blkid_probe_lookup_value(b, "TYPE", &v, NULL);
        if (r != 0)
                return log_error_errno(errno ?: EIO, "Failed to probe file system type \"%s\": %m", p);
        if (!streq(v, "vfat")) {
                log_error("File system \"%s\" is not FAT.", p);
                return -ENODEV;
        }

        errno = 0;
        r = blkid_probe_lookup_value(b, "PART_ENTRY_SCHEME", &v, NULL);
        if (r != 0)
                return log_error_errno(errno ?: EIO, "Failed to probe partition scheme \"%s\": %m", p);
        if (!streq(v, "gpt")) {
                log_error("File system \"%s\" is not on a GPT partition table.", p);
                return -ENODEV;
        }

        errno = 0;
        r = blkid_probe_lookup_value(b, "PART_ENTRY_TYPE", &v, NULL);
        if (r != 0)
                return log_error_errno(errno ?: EIO, "Failed to probe partition type UUID \"%s\": %m", p);
        if (!streq(v, "c12a7328-f81f-11d2-ba4b-00a0c93ec93b")) {
                log_error("File system \"%s\" has wrong type for an EFI System Partition (ESP).", p);
                return -ENODEV;
        }

        errno = 0;
        r = blkid_probe_lookup_value(b, "PART_ENTRY_UUID", &v, NULL);
        if (r != 0)
                return log_error_errno(errno ?: EIO, "Failed to probe partition entry UUID \"%s\": %m", p);
        r = sd_id128_from_string(v, &uuid);
        if (r < 0) {
                log_error("Partition \"%s\" has invalid UUID \"%s\".", p, v);
                return -EIO;
        }

        errno = 0;
        r = blkid_probe_lookup_value(b, "PART_ENTRY_NUMBER", &v, NULL);
        if (r != 0)
                return log_error_errno(errno ?: EIO, "Failed to probe partition number \"%s\": m", p);
        r = safe_atou32(v, &part);
        if (r < 0)
                return log_error_errno(r, "Failed to parse PART_ENTRY_NUMBER field.");

        errno = 0;
        r = blkid_probe_lookup_value(b, "PART_ENTRY_OFFSET", &v, NULL);
        if (r != 0)
                return log_error_errno(errno ?: EIO, "Failed to probe partition offset \"%s\": %m", p);
        r = safe_atou64(v, &pstart);
        if (r < 0)
                return log_error_errno(r, "Failed to parse PART_ENTRY_OFFSET field.");

        errno = 0;
        r = blkid_probe_lookup_value(b, "PART_ENTRY_SIZE", &v, NULL);
        if (r != 0)
                return log_error_errno(errno ?: EIO, "Failed to probe partition size \"%s\": %m", p);
        r = safe_atou64(v, &psize);
        if (r < 0)
                return log_error_errno(r, "Failed to parse PART_ENTRY_SIZE field.");
#endif

finish:
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

int find_default_boot_entry(
                const char *esp_path,
                char **esp_where,
                BootConfig *config,
                const BootEntry **e) {

        _cleanup_free_ char *where = NULL;
        int r;

        assert(config);
        assert(e);

        r = find_esp_and_warn(esp_path, false, &where, NULL, NULL, NULL, NULL);
        if (r < 0)
                return r;

        r = boot_entries_load_config(where, config);
        if (r < 0)
                return log_error_errno(r, "Failed to load bootspec config from \"%s/loader\": %m", where);

        if (config->default_entry < 0) {
                log_error("No entry suitable as default, refusing to guess.");
                return -ENOENT;
        }

        *e = &config->entries[config->default_entry];
        log_debug("Found default boot entry in file \"%s\"", (*e)->path);

        if (esp_where)
                *esp_where = TAKE_PTR(where);

        return 0;
}
