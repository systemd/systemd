/***
  This file is part of systemd.

  Copyright 2017 Zbigniew Jędrzejewski-Szmek

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

#include <stdio.h>

#include "alloc-util.h"
#include "bootspec.h"
#include "conf-files.h"
#include "def.h"
#include "efivars.h"
#include "fd-util.h"
#include "fileio.h"
#include "string-util.h"
#include "strv.h"

void boot_entry_free(BootEntry *entry) {
        free(entry->filename);

        free(entry->title);
        free(entry->version);
        free(entry->machine_id);
        free(entry->architecture);
        strv_free(entry->options);
        free(entry->kernel);
        free(entry->efi);
        strv_free(entry->initrd);
        free(entry->device_tree);
}

int boot_entry_load(const char *path, BootEntry *entry) {
        _cleanup_fclose_ FILE *f = NULL;
        unsigned line = 1;
        _cleanup_(boot_entry_free) BootEntry tmp = {};
        int r;

        f = fopen(path, "re");
        if (!f)
                return log_error_errno(errno, "Failed to open \"%s\": %m", path);

        tmp.filename = strdup(basename(path));
        if (!tmp.filename)
                return log_oom();

        for (;;) {
                _cleanup_free_ char *buf = NULL;
                char *p;

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

                p = strchr(buf, ' ');
                if (!p) {
                        log_warning("%s:%u: Bad syntax", path, line);
                        continue;
                }
                *p = '\0';
                p = strstrip(p + 1);

                if (streq(buf, "title"))
                        r = free_and_strdup(&tmp.title, p);
                else if (streq(buf, "version"))
                        r = free_and_strdup(&tmp.version, p);
                else if (streq(buf, "machine-id"))
                        r = free_and_strdup(&tmp.machine_id, p);
                else if (streq(buf, "architecture"))
                        r = free_and_strdup(&tmp.architecture, p);
                else if (streq(buf, "options"))
                        r = strv_extend(&tmp.options, p);
                else if (streq(buf, "linux"))
                        r = free_and_strdup(&tmp.kernel, p);
                else if (streq(buf, "efi"))
                        r = free_and_strdup(&tmp.efi, p);
                else if (streq(buf, "initrd"))
                        r = strv_extend(&tmp.initrd, p);
                else if (streq(buf, "devicetree"))
                        r = free_and_strdup(&tmp.device_tree, p);
                else {
                        log_notice("%s:%u: Unknown line \"%s\"", path, line, buf);
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
        unsigned i;

        free(config->default_pattern);
        free(config->timeout);
        free(config->editor);

        free(config->entry_oneshot);
        free(config->entry_default);

        for (i = 0; i < config->n_entries; i++)
                boot_entry_free(config->entries + i);
        free(config->entries);
}

int boot_loader_read_conf(const char *path, BootConfig *config) {
        _cleanup_fclose_ FILE *f = NULL;
        unsigned line = 1;
        int r;

        f = fopen(path, "re");
        if (!f)
                return log_error_errno(errno, "Failed to open \"%s\": %m", path);

        for (;;) {
                _cleanup_free_ char *buf = NULL;
                char *p;

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

                p = strchr(buf, ' ');
                if (!p) {
                        log_warning("%s:%u: Bad syntax", path, line);
                        continue;
                }
                *p = '\0';
                p = strstrip(p + 1);

                if (streq(buf, "default"))
                        r = free_and_strdup(&config->default_pattern, p);
                else if (streq(buf, "timeout"))
                        r = free_and_strdup(&config->timeout, p);
                else if (streq(buf, "editor"))
                        r = free_and_strdup(&config->editor, p);
                else {
                        log_notice("%s:%u: Unknown line \"%s\"", path, line, buf);
                        continue;
                }
                if (r < 0)
                        return log_error_errno(r, "%s:%u: Error while reading: %m", path, line);
        }

        return 0;
}

/* This is a direct translation of str_verscmp from boot.c */
static bool is_digit(int c) {
        return c >= '0' && c <= '9';
}

static int c_order(int c) {
        if (c == '\0')
                return 0;
        if (is_digit(c))
                return 0;
        else if ((c >= 'a') && (c <= 'z'))
                return c;
        else
                return c + 0x10000;
}

static int str_verscmp(const char *s1, const char *s2) {
        const char *os1 = s1;
        const char *os2 = s2;

        while (*s1 || *s2) {
                int first;

                while ((*s1 && !is_digit(*s1)) || (*s2 && !is_digit(*s2))) {
                        int order;

                        order = c_order(*s1) - c_order(*s2);
                        if (order)
                                return order;
                        s1++;
                        s2++;
                }

                while (*s1 == '0')
                        s1++;
                while (*s2 == '0')
                        s2++;

                first = 0;
                while (is_digit(*s1) && is_digit(*s2)) {
                        if (first == 0)
                                first = *s1 - *s2;
                        s1++;
                        s2++;
                }

                if (is_digit(*s1))
                        return 1;
                if (is_digit(*s2))
                        return -1;

                if (first != 0)
                        return first;
        }

        return strcmp(os1, os2);
}

static int boot_entry_compare(const void *a, const void *b) {
        const BootEntry *aa = a;
        const BootEntry *bb = b;

        return str_verscmp(aa->filename, bb->filename);
}

int boot_entries_find(const char *dir, BootEntry **entries, size_t *n_entries) {
        _cleanup_strv_free_ char **files = NULL;
        char **f;
        int r;

        BootEntry *array = NULL;
        size_t n_allocated = 0, n = 0;

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

        qsort_safe(array, n, sizeof(BootEntry), boot_entry_compare);

        *entries = array;
        *n_entries = n;
        return 0;
}

int boot_entries_select_default(const BootConfig *config) {
        int i;

        if (config->entry_oneshot)
                for (i = config->n_entries - 1; i >= 0; i--)
                        if (streq(config->entry_oneshot, config->entries[i].filename)) {
                                log_debug("Found default: filename \"%s\" is matched by LoaderEntryOneShot",
                                          config->entries[i].filename);
                                return i;
                        }

        if (config->entry_default)
                for (i = config->n_entries - 1; i >= 0; i--)
                        if (streq(config->entry_default, config->entries[i].filename)) {
                                log_debug("Found default: filename \"%s\" is matched by LoaderEntryDefault",
                                          config->entries[i].filename);
                                return i;
                        }

        if (config->default_pattern)
                for (i = config->n_entries - 1; i >= 0; i--)
                        if (fnmatch(config->default_pattern, config->entries[i].filename, FNM_CASEFOLD) == 0) {
                                log_debug("Found default: filename \"%s\" is matched by pattern \"%s\"",
                                          config->entries[i].filename, config->default_pattern);
                                return i;
                        }

        if (config->n_entries > 0)
                log_debug("Found default: last entry \"%s\"", config->entries[i].filename);
        else
                log_debug("Found no default boot entry :(");
        return config->n_entries - 1; /* -1 means "no default" */
}

int boot_entries_load_config(const char *esp_path, BootConfig *config) {
        const char *p;
        int r;

        p = strjoina(esp_path, "/loader/loader.conf");
        r = boot_loader_read_conf(p, config);
        if (r < 0)
                return log_error_errno(r, "Failed to read boot config from \"%s\": %m", p);

        p = strjoina(esp_path, "/loader/entries");
        r = boot_entries_find(p, &config->entries, &config->n_entries);
        if (r < 0)
                return log_error_errno(r, "Failed to read boot entries from \"%s\": %m", p);

        r = efi_get_variable_string(EFI_VENDOR_LOADER, "LoaderEntryOneShot", &config->entry_oneshot);
        if (r < 0 && r != -ENOENT)
                return log_error_errno(r, "Failed to read EFI var \"LoaderEntryOneShot\": %m");

        r = efi_get_variable_string(EFI_VENDOR_LOADER, "LoaderEntryDefault", &config->entry_default);
        if (r < 0 && r != -ENOENT)
                return log_error_errno(r, "Failed to read EFI var \"LoaderEntryDefault\": %m");

        config->default_entry = boot_entries_select_default(config);
        return 0;
}
