/* SPDX-License-Identifier: LGPL-2.1+ */

#include <ctype.h>
#include <errno.h>
#include <ftw.h>
#include <getopt.h>
#include <limits.h>
#include <linux/magic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#include "sd-id128.h"

#include "alloc-util.h"
#include "blkid-util.h"
#include "bootspec.h"
#include "copy.h"
#include "dirent-util.h"
#include "efivars.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "locale-util.h"
#include "main-func.h"
#include "pager.h"
#include "parse-util.h"
#include "pretty-print.h"
#include "rm-rf.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "tmpfile-util.h"
#include "umask-util.h"
#include "utf8.h"
#include "util.h"
#include "verbs.h"
#include "virt.h"

static char *arg_path = NULL;
static bool arg_print_path = false;
static bool arg_touch_variables = true;
static PagerFlags arg_pager_flags = 0;

STATIC_DESTRUCTOR_REGISTER(arg_path, freep);

static int acquire_esp(
                bool unprivileged_mode,
                uint32_t *ret_part,
                uint64_t *ret_pstart,
                uint64_t *ret_psize,
                sd_id128_t *ret_uuid) {

        char *np;
        int r;

        /* Find the ESP, and log about errors. Note that find_esp_and_warn() will log in all error cases on its own,
         * except for ENOKEY (which is good, we want to show our own message in that case, suggesting use of --path=)
         * and EACCESS (only when we request unprivileged mode; in this case we simply eat up the error here, so that
         * --list and --status work too, without noise about this). */

        r = find_esp_and_warn(arg_path, unprivileged_mode, &np, ret_part, ret_pstart, ret_psize, ret_uuid);
        if (r == -ENOKEY)
                return log_error_errno(r,
                                       "Couldn't find EFI system partition. It is recommended to mount it to /boot or /efi.\n"
                                       "Alternatively, use --path= to specify path to mount point.");
        if (r < 0)
                return r;

        free_and_replace(arg_path, np);

        log_debug("Using EFI System Partition at %s.", arg_path);

        return 0;
}

/* search for "#### LoaderInfo: systemd-boot 218 ####" string inside the binary */
static int get_file_version(int fd, char **v) {
        struct stat st;
        char *buf;
        const char *s, *e;
        char *x = NULL;
        int r = 0;

        assert(fd >= 0);
        assert(v);

        if (fstat(fd, &st) < 0)
                return log_error_errno(errno, "Failed to stat EFI binary: %m");

        if (st.st_size < 27) {
                *v = NULL;
                return 0;
        }

        buf = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (buf == MAP_FAILED)
                return log_error_errno(errno, "Failed to memory map EFI binary: %m");

        s = memmem(buf, st.st_size - 8, "#### LoaderInfo: ", 17);
        if (!s)
                goto finish;
        s += 17;

        e = memmem(s, st.st_size - (s - buf), " ####", 5);
        if (!e || e - s < 3) {
                log_error("Malformed version string.");
                r = -EINVAL;
                goto finish;
        }

        x = strndup(s, e - s);
        if (!x) {
                r = log_oom();
                goto finish;
        }
        r = 1;

finish:
        (void) munmap(buf, st.st_size);
        *v = x;
        return r;
}

static int enumerate_binaries(const char *esp_path, const char *path, const char *prefix) {
        char *p;
        _cleanup_closedir_ DIR *d = NULL;
        struct dirent *de;
        int r = 0, c = 0;

        p = strjoina(esp_path, "/", path);
        d = opendir(p);
        if (!d) {
                if (errno == ENOENT)
                        return 0;

                return log_error_errno(errno, "Failed to read \"%s\": %m", p);
        }

        FOREACH_DIRENT(de, d, break) {
                _cleanup_close_ int fd = -1;
                _cleanup_free_ char *v = NULL;

                if (!endswith_no_case(de->d_name, ".efi"))
                        continue;

                if (prefix && !startswith_no_case(de->d_name, prefix))
                        continue;

                fd = openat(dirfd(d), de->d_name, O_RDONLY|O_CLOEXEC);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to open \"%s/%s\" for reading: %m", p, de->d_name);

                r = get_file_version(fd, &v);
                if (r < 0)
                        return r;
                if (r > 0)
                        printf("         File: %s/%s/%s (%s%s%s)\n", special_glyph(SPECIAL_GLYPH_TREE_RIGHT), path, de->d_name, ansi_highlight(), v, ansi_normal());
                else
                        printf("         File: %s/%s/%s\n", special_glyph(SPECIAL_GLYPH_TREE_RIGHT), path, de->d_name);
                c++;
        }

        return c;
}

static int status_binaries(const char *esp_path, sd_id128_t partition) {
        int r;

        printf("Available Boot Loaders on ESP:\n");

        if (!esp_path) {
                printf("          ESP: Cannot find or access mount point of ESP.\n\n");
                return -ENOENT;
        }

        printf("          ESP: %s", esp_path);
        if (!sd_id128_is_null(partition))
                printf(" (/dev/disk/by-partuuid/%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x)", SD_ID128_FORMAT_VAL(partition));
        printf("\n");

        r = enumerate_binaries(esp_path, "EFI/systemd", NULL);
        if (r == 0)
                log_info("systemd-boot not installed in ESP.");
        else if (r < 0)
                return r;

        r = enumerate_binaries(esp_path, "EFI/BOOT", "boot");
        if (r == 0)
                log_info("No default/fallback boot loader installed in ESP.");
        else if (r < 0)
                return r;

        printf("\n");

        return 0;
}

static int print_efi_option(uint16_t id, bool in_order) {
        _cleanup_free_ char *title = NULL;
        _cleanup_free_ char *path = NULL;
        sd_id128_t partition;
        bool active;
        int r = 0;

        r = efi_get_boot_option(id, &title, &partition, &path, &active);
        if (r < 0)
                return r;

        /* print only configured entries with partition information */
        if (!path || sd_id128_is_null(partition))
                return 0;

        efi_tilt_backslashes(path);

        printf("        Title: %s%s%s\n", ansi_highlight(), strna(title), ansi_normal());
        printf("           ID: 0x%04X\n", id);
        printf("       Status: %sactive%s\n", active ? "" : "in", in_order ? ", boot-order" : "");
        printf("    Partition: /dev/disk/by-partuuid/%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x\n", SD_ID128_FORMAT_VAL(partition));
        printf("         File: %s%s\n", special_glyph(SPECIAL_GLYPH_TREE_RIGHT), path);
        printf("\n");

        return 0;
}

static int status_variables(void) {
        _cleanup_free_ uint16_t *options = NULL, *order = NULL;
        int n_options, n_order, i;

        n_options = efi_get_boot_options(&options);
        if (n_options == -ENOENT)
                return log_error_errno(n_options,
                                       "Failed to access EFI variables, efivarfs"
                                       " needs to be available at /sys/firmware/efi/efivars/.");
        if (n_options < 0)
                return log_error_errno(n_options, "Failed to read EFI boot entries: %m");

        n_order = efi_get_boot_order(&order);
        if (n_order == -ENOENT)
                n_order = 0;
        else if (n_order < 0)
                return log_error_errno(n_order, "Failed to read EFI boot order: %m");

        /* print entries in BootOrder first */
        printf("Boot Loaders Listed in EFI Variables:\n");
        for (i = 0; i < n_order; i++)
                print_efi_option(order[i], true);

        /* print remaining entries */
        for (i = 0; i < n_options; i++) {
                int j;

                for (j = 0; j < n_order; j++)
                        if (options[i] == order[j])
                                goto next_option;

                print_efi_option(options[i], false);

        next_option:
                continue;
        }

        return 0;
}

static int boot_entry_show(const BootEntry *e, bool show_as_default) {
        assert(e);

        printf("        title: %s%s%s%s%s%s\n",
               ansi_highlight(),
               boot_entry_title(e),
               ansi_normal(),
               ansi_highlight_green(),
               show_as_default ? " (default)" : "",
               ansi_normal());

        if (e->id)
                printf("           id: %s\n", e->id);
        if (e->version)
                printf("      version: %s\n", e->version);
        if (e->machine_id)
                printf("   machine-id: %s\n", e->machine_id);
        if (e->architecture)
                printf(" architecture: %s\n", e->architecture);
        if (e->kernel)
                printf("        linux: %s\n", e->kernel);
        if (!strv_isempty(e->initrd)) {
                _cleanup_free_ char *t;

                t = strv_join(e->initrd, " ");
                if (!t)
                        return log_oom();

                printf("       initrd: %s\n", t);
        }
        if (!strv_isempty(e->options)) {
                _cleanup_free_ char *t;

                t = strv_join(e->options, " ");
                if (!t)
                        return log_oom();

                printf("      options: %s\n", t);
        }
        if (e->device_tree)
                printf("   devicetree: %s\n", e->device_tree);

        return 0;
}

static int status_entries(const char *esp_path, sd_id128_t partition) {
        _cleanup_(boot_config_free) BootConfig config = {};
        int r;

        r = boot_entries_load_config(esp_path, &config);
        if (r < 0)
                return r;

        if (config.default_entry < 0)
                printf("%zu entries, no entry could be determined as default.\n", config.n_entries);
        else {
                printf("Default Boot Loader Entry:\n");

                boot_entry_show(config.entries + config.default_entry, false);
        }

        return 0;
}

static int compare_product(const char *a, const char *b) {
        size_t x, y;

        assert(a);
        assert(b);

        x = strcspn(a, " ");
        y = strcspn(b, " ");
        if (x != y)
                return x < y ? -1 : x > y ? 1 : 0;

        return strncmp(a, b, x);
}

static int compare_version(const char *a, const char *b) {
        assert(a);
        assert(b);

        a += strcspn(a, " ");
        a += strspn(a, " ");
        b += strcspn(b, " ");
        b += strspn(b, " ");

        return strverscmp(a, b);
}

static int version_check(int fd_from, const char *from, int fd_to, const char *to) {
        _cleanup_free_ char *a = NULL, *b = NULL;
        int r;

        assert(fd_from >= 0);
        assert(from);
        assert(fd_to >= 0);
        assert(to);

        r = get_file_version(fd_from, &a);
        if (r < 0)
                return r;
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Source file \"%s\" does not carry version information!",
                                       from);

        r = get_file_version(fd_to, &b);
        if (r < 0)
                return r;
        if (r == 0 || compare_product(a, b) != 0)
                return log_notice_errno(SYNTHETIC_ERRNO(EEXIST),
                                        "Skipping \"%s\", since it's owned by another boot loader.",
                                        to);

        if (compare_version(a, b) < 0) {
                log_warning("Skipping \"%s\", since a newer boot loader version exists already.", to);
                return -ESTALE;
        }

        return 0;
}

static int copy_file_with_version_check(const char *from, const char *to, bool force) {
        _cleanup_close_ int fd_from = -1, fd_to = -1;
        _cleanup_free_ char *t = NULL;
        int r;

        fd_from = open(from, O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (fd_from < 0)
                return log_error_errno(errno, "Failed to open \"%s\" for reading: %m", from);

        if (!force) {
                fd_to = open(to, O_RDONLY|O_CLOEXEC|O_NOCTTY);
                if (fd_to < 0) {
                        if (errno != -ENOENT)
                                return log_error_errno(errno, "Failed to open \"%s\" for reading: %m", to);
                } else {
                        r = version_check(fd_from, from, fd_to, to);
                        if (r < 0)
                                return r;

                        if (lseek(fd_from, 0, SEEK_SET) == (off_t) -1)
                                return log_error_errno(errno, "Failed to seek in \"%s\": %m", from);

                        fd_to = safe_close(fd_to);
                }
        }

        r = tempfn_random(to, NULL, &t);
        if (r < 0)
                return log_oom();

        RUN_WITH_UMASK(0000) {
                fd_to = open(t, O_WRONLY|O_CREAT|O_CLOEXEC|O_EXCL|O_NOFOLLOW, 0644);
                if (fd_to < 0)
                        return log_error_errno(errno, "Failed to open \"%s\" for writing: %m", t);
        }

        r = copy_bytes(fd_from, fd_to, (uint64_t) -1, COPY_REFLINK);
        if (r < 0) {
                (void) unlink(t);
                return log_error_errno(r, "Failed to copy data from \"%s\" to \"%s\": %m", from, t);
        }

        (void) copy_times(fd_from, fd_to);

        if (fsync(fd_to) < 0) {
                (void) unlink_noerrno(t);
                return log_error_errno(errno, "Failed to copy data from \"%s\" to \"%s\": %m", from, t);
        }

        (void) fsync_directory_of_file(fd_to);

        if (renameat(AT_FDCWD, t, AT_FDCWD, to) < 0) {
                (void) unlink_noerrno(t);
                return log_error_errno(errno, "Failed to rename \"%s\" to \"%s\": %m", t, to);
        }

        log_info("Copied \"%s\" to \"%s\".", from, to);

        return 0;
}

static int mkdir_one(const char *prefix, const char *suffix) {
        char *p;

        p = strjoina(prefix, "/", suffix);
        if (mkdir(p, 0700) < 0) {
                if (errno != EEXIST)
                        return log_error_errno(errno, "Failed to create \"%s\": %m", p);
        } else
                log_info("Created \"%s\".", p);

        return 0;
}

static const char *efi_subdirs[] = {
        "EFI",
        "EFI/systemd",
        "EFI/BOOT",
        "loader",
        "loader/entries",
        NULL
};

static int create_dirs(const char *esp_path) {
        const char **i;
        int r;

        STRV_FOREACH(i, efi_subdirs) {
                r = mkdir_one(esp_path, *i);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int copy_one_file(const char *esp_path, const char *name, bool force) {
        char *p, *q;
        int r;

        p = strjoina(BOOTLIBDIR "/", name);
        q = strjoina(esp_path, "/EFI/systemd/", name);
        r = copy_file_with_version_check(p, q, force);

        if (startswith(name, "systemd-boot")) {
                int k;
                char *v;

                /* Create the EFI default boot loader name (specified for removable devices) */
                v = strjoina(esp_path, "/EFI/BOOT/BOOT",
                             name + STRLEN("systemd-boot"));
                ascii_strupper(strrchr(v, '/') + 1);

                k = copy_file_with_version_check(p, v, force);
                if (k < 0 && r == 0)
                        r = k;
        }

        return r;
}

static int install_binaries(const char *esp_path, bool force) {
        struct dirent *de;
        _cleanup_closedir_ DIR *d = NULL;
        int r = 0;

        if (force) {
                /* Don't create any of these directories when we are
                 * just updating. When we update we'll drop-in our
                 * files (unless there are newer ones already), but we
                 * won't create the directories for them in the first
                 * place. */
                r = create_dirs(esp_path);
                if (r < 0)
                        return r;
        }

        d = opendir(BOOTLIBDIR);
        if (!d)
                return log_error_errno(errno, "Failed to open \""BOOTLIBDIR"\": %m");

        FOREACH_DIRENT(de, d, break) {
                int k;

                if (!endswith_no_case(de->d_name, ".efi"))
                        continue;

                k = copy_one_file(esp_path, de->d_name, force);
                if (k < 0 && r == 0)
                        r = k;
        }

        return r;
}

static bool same_entry(uint16_t id, const sd_id128_t uuid, const char *path) {
        _cleanup_free_ char *opath = NULL;
        sd_id128_t ouuid;
        int r;

        r = efi_get_boot_option(id, NULL, &ouuid, &opath, NULL);
        if (r < 0)
                return false;
        if (!sd_id128_equal(uuid, ouuid))
                return false;
        if (!streq_ptr(path, opath))
                return false;

        return true;
}

static int find_slot(sd_id128_t uuid, const char *path, uint16_t *id) {
        _cleanup_free_ uint16_t *options = NULL;
        int n, i;

        n = efi_get_boot_options(&options);
        if (n < 0)
                return n;

        /* find already existing systemd-boot entry */
        for (i = 0; i < n; i++)
                if (same_entry(options[i], uuid, path)) {
                        *id = options[i];
                        return 1;
                }

        /* find free slot in the sorted BootXXXX variable list */
        for (i = 0; i < n; i++)
                if (i != options[i]) {
                        *id = i;
                        return 1;
                }

        /* use the next one */
        if (i == 0xffff)
                return -ENOSPC;
        *id = i;
        return 0;
}

static int insert_into_order(uint16_t slot, bool first) {
        _cleanup_free_ uint16_t *order = NULL;
        uint16_t *t;
        int n, i;

        n = efi_get_boot_order(&order);
        if (n <= 0)
                /* no entry, add us */
                return efi_set_boot_order(&slot, 1);

        /* are we the first and only one? */
        if (n == 1 && order[0] == slot)
                return 0;

        /* are we already in the boot order? */
        for (i = 0; i < n; i++) {
                if (order[i] != slot)
                        continue;

                /* we do not require to be the first one, all is fine */
                if (!first)
                        return 0;

                /* move us to the first slot */
                memmove(order + 1, order, i * sizeof(uint16_t));
                order[0] = slot;
                return efi_set_boot_order(order, n);
        }

        /* extend array */
        t = realloc(order, (n + 1) * sizeof(uint16_t));
        if (!t)
                return -ENOMEM;
        order = t;

        /* add us to the top or end of the list */
        if (first) {
                memmove(order + 1, order, n * sizeof(uint16_t));
                order[0] = slot;
        } else
                order[n] = slot;

        return efi_set_boot_order(order, n + 1);
}

static int remove_from_order(uint16_t slot) {
        _cleanup_free_ uint16_t *order = NULL;
        int n, i;

        n = efi_get_boot_order(&order);
        if (n <= 0)
                return n;

        for (i = 0; i < n; i++) {
                if (order[i] != slot)
                        continue;

                if (i + 1 < n)
                        memmove(order + i, order + i+1, (n - i) * sizeof(uint16_t));
                return efi_set_boot_order(order, n - 1);
        }

        return 0;
}

static int install_variables(const char *esp_path,
                             uint32_t part, uint64_t pstart, uint64_t psize,
                             sd_id128_t uuid, const char *path,
                             bool first) {
        char *p;
        uint16_t slot;
        int r;

        if (!is_efi_boot()) {
                log_warning("Not booted with EFI, skipping EFI variable setup.");
                return 0;
        }

        p = strjoina(esp_path, path);
        if (access(p, F_OK) < 0) {
                if (errno == ENOENT)
                        return 0;

                return log_error_errno(errno, "Cannot access \"%s\": %m", p);
        }

        r = find_slot(uuid, path, &slot);
        if (r < 0)
                return log_error_errno(r,
                                       r == -ENOENT ?
                                       "Failed to access EFI variables. Is the \"efivarfs\" filesystem mounted?" :
                                       "Failed to determine current boot order: %m");

        if (first || r == 0) {
                r = efi_add_boot_option(slot, "Linux Boot Manager",
                                        part, pstart, psize,
                                        uuid, path);
                if (r < 0)
                        return log_error_errno(r, "Failed to create EFI Boot variable entry: %m");

                log_info("Created EFI boot entry \"Linux Boot Manager\".");
        }

        return insert_into_order(slot, first);
}

static int remove_boot_efi(const char *esp_path) {
        char *p;
        _cleanup_closedir_ DIR *d = NULL;
        struct dirent *de;
        int r, c = 0;

        p = strjoina(esp_path, "/EFI/BOOT");
        d = opendir(p);
        if (!d) {
                if (errno == ENOENT)
                        return 0;

                return log_error_errno(errno, "Failed to open directory \"%s\": %m", p);
        }

        FOREACH_DIRENT(de, d, break) {
                _cleanup_close_ int fd = -1;
                _cleanup_free_ char *v = NULL;

                if (!endswith_no_case(de->d_name, ".efi"))
                        continue;

                if (!startswith_no_case(de->d_name, "boot"))
                        continue;

                fd = openat(dirfd(d), de->d_name, O_RDONLY|O_CLOEXEC);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to open \"%s/%s\" for reading: %m", p, de->d_name);

                r = get_file_version(fd, &v);
                if (r < 0)
                        return r;
                if (r > 0 && startswith(v, "systemd-boot ")) {
                        r = unlinkat(dirfd(d), de->d_name, 0);
                        if (r < 0)
                                return log_error_errno(errno, "Failed to remove \"%s/%s\": %m", p, de->d_name);

                        log_info("Removed \"%s/%s\".", p, de->d_name);
                }

                c++;
        }

        return c;
}

static int rmdir_one(const char *prefix, const char *suffix) {
        char *p;

        p = strjoina(prefix, "/", suffix);
        if (rmdir(p) < 0) {
                if (!IN_SET(errno, ENOENT, ENOTEMPTY))
                        return log_error_errno(errno, "Failed to remove \"%s\": %m", p);
        } else
                log_info("Removed \"%s\".", p);

        return 0;
}

static int remove_binaries(const char *esp_path) {
        char *p;
        int r, q;
        unsigned i;

        p = strjoina(esp_path, "/EFI/systemd");
        r = rm_rf(p, REMOVE_ROOT|REMOVE_PHYSICAL);

        q = remove_boot_efi(esp_path);
        if (q < 0 && r == 0)
                r = q;

        for (i = ELEMENTSOF(efi_subdirs)-1; i > 0; i--) {
                q = rmdir_one(esp_path, efi_subdirs[i-1]);
                if (q < 0 && r == 0)
                        r = q;
        }

        return r;
}

static int remove_variables(sd_id128_t uuid, const char *path, bool in_order) {
        uint16_t slot;
        int r;

        if (!is_efi_boot())
                return 0;

        r = find_slot(uuid, path, &slot);
        if (r != 1)
                return 0;

        r = efi_remove_boot_option(slot);
        if (r < 0)
                return r;

        if (in_order)
                return remove_from_order(slot);

        return 0;
}

static int install_loader_config(const char *esp_path) {

        char machine_string[SD_ID128_STRING_MAX];
        _cleanup_(unlink_and_freep) char *t = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        sd_id128_t machine_id;
        const char *p;
        int r, fd;

        r = sd_id128_get_machine(&machine_id);
        if (r < 0)
                return log_error_errno(r, "Failed to get machine id: %m");

        p = strjoina(esp_path, "/loader/loader.conf");

        if (access(p, F_OK) >= 0) /* Silently skip creation if the file already exists (early check) */
                return 0;

        fd = open_tmpfile_linkable(p, O_WRONLY|O_CLOEXEC, &t);
        if (fd < 0)
                return log_error_errno(fd, "Failed to open \"%s\" for writing: %m", p);

        f = fdopen(fd, "w");
        if (!f) {
                safe_close(fd);
                return log_oom();
        }

        fprintf(f, "#timeout 3\n"
                   "#console-mode keep\n"
                   "default %s-*\n", sd_id128_to_string(machine_id, machine_string));

        r = fflush_sync_and_check(f);
        if (r < 0)
                return log_error_errno(r, "Failed to write \"%s\": %m", p);

        r = link_tmpfile(fd, t, p);
        if (r == -EEXIST)
                return 0; /* Silently skip creation if the file exists now (recheck) */
        if (r < 0)
                return log_error_errno(r, "Failed to move \"%s\" into place: %m", p);

        t = mfree(t);

        return 1;
}

static int help(int argc, char *argv[], void *userdata) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("bootctl", "1", &link);
        if (r < 0)
                return log_oom();

        printf("%s [COMMAND] [OPTIONS...]\n\n"
               "Install, update or remove the systemd-boot EFI boot manager.\n\n"
               "  -h --help          Show this help\n"
               "     --version       Print version\n"
               "     --path=PATH     Path to the EFI System Partition (ESP)\n"
               "  -p --print-path    Print path to the EFI partition\n"
               "     --no-variables  Don't touch EFI variables\n"
               "     --no-pager      Do not pipe output into a pager\n"
               "\nBoot Loader Commands:\n"
               "     status          Show status of installed systemd-boot and EFI variables\n"
               "     install         Install systemd-boot to the ESP and EFI variables\n"
               "     update          Update systemd-boot in the ESP and EFI variables\n"
               "     remove          Remove systemd-boot from the ESP and EFI variables\n"
               "\nBoot Loader Entries Commands:\n"
               "     list            List boot loader entries\n"
               "     set-default ID  Set default boot loader entry\n"
               "     set-oneshot ID  Set default boot loader entry, for next boot only\n"
               "\nSee the %s for details.\n"
               , program_invocation_short_name
               , link);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_PATH = 0x100,
                ARG_VERSION,
                ARG_NO_VARIABLES,
                ARG_NO_PAGER,
        };

        static const struct option options[] = {
                { "help",         no_argument,       NULL, 'h'              },
                { "version",      no_argument,       NULL, ARG_VERSION      },
                { "path",         required_argument, NULL, ARG_PATH         },
                { "print-path",   no_argument,       NULL, 'p'              },
                { "no-variables", no_argument,       NULL, ARG_NO_VARIABLES },
                { "no-pager",     no_argument,       NULL, ARG_NO_PAGER     },
                {}
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hp", options, NULL)) >= 0)
                switch (c) {

                case 'h':
                        help(0, NULL, NULL);
                        return 0;

                case ARG_VERSION:
                        return version();

                case ARG_PATH:
                        r = free_and_strdup(&arg_path, optarg);
                        if (r < 0)
                                return log_oom();
                        break;

                case 'p':
                        arg_print_path = true;
                        break;

                case ARG_NO_VARIABLES:
                        arg_touch_variables = false;
                        break;

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unknown option");
                }

        return 1;
}

static void read_loader_efi_var(const char *name, char **var) {
        int r;

        r = efi_get_variable_string(EFI_VENDOR_LOADER, name, var);
        if (r < 0 && r != -ENOENT)
                log_warning_errno(r, "Failed to read EFI variable %s: %m", name);
}

static int verb_status(int argc, char *argv[], void *userdata) {

        sd_id128_t uuid = SD_ID128_NULL;
        int r, k;

        r = acquire_esp(geteuid() != 0, NULL, NULL, NULL, &uuid);

        if (arg_print_path) {
                if (r == -EACCES) /* If we couldn't acquire the ESP path, log about access errors (which is the only
                                   * error the find_esp_and_warn() won't log on its own) */
                        return log_error_errno(r, "Failed to determine ESP: %m");
                if (r < 0)
                        return r;

                puts(arg_path);
                return 0;
        }

        r = 0; /* If we couldn't determine the path, then don't consider that a problem from here on, just show what we
                * can show */

        (void) pager_open(arg_pager_flags);

        if (is_efi_boot()) {
                static const struct {
                        uint64_t flag;
                        const char *name;
                } flags[] = {
                        { EFI_LOADER_FEATURE_BOOT_COUNTING,           "Boot counting"                 },
                        { EFI_LOADER_FEATURE_CONFIG_TIMEOUT,          "Menu timeout control"          },
                        { EFI_LOADER_FEATURE_CONFIG_TIMEOUT_ONE_SHOT, "One-shot menu timeout control" },
                        { EFI_LOADER_FEATURE_ENTRY_DEFAULT,           "Default entry control"         },
                        { EFI_LOADER_FEATURE_ENTRY_ONESHOT,           "One-shot entry control"        },
                };

                _cleanup_free_ char *fw_type = NULL, *fw_info = NULL, *loader = NULL, *loader_path = NULL, *stub = NULL;
                sd_id128_t loader_part_uuid = SD_ID128_NULL;
                uint64_t loader_features = 0;
                size_t i;

                read_loader_efi_var("LoaderFirmwareType", &fw_type);
                read_loader_efi_var("LoaderFirmwareInfo", &fw_info);
                read_loader_efi_var("LoaderInfo", &loader);
                read_loader_efi_var("StubInfo", &stub);
                read_loader_efi_var("LoaderImageIdentifier", &loader_path);
                (void) efi_loader_get_features(&loader_features);

                if (loader_path)
                        efi_tilt_backslashes(loader_path);

                k = efi_loader_get_device_part_uuid(&loader_part_uuid);
                if (k < 0 && k != -ENOENT)
                        r = log_warning_errno(k, "Failed to read EFI variable LoaderDevicePartUUID: %m");

                printf("System:\n");
                printf("     Firmware: %s%s (%s)%s\n", ansi_highlight(), strna(fw_type), strna(fw_info), ansi_normal());
                printf("  Secure Boot: %sd\n", enable_disable(is_efi_secure_boot()));
                printf("   Setup Mode: %s\n", is_efi_secure_boot_setup_mode() ? "setup" : "user");
                printf("\n");

                printf("Current Boot Loader:\n");
                printf("      Product: %s%s%s\n", ansi_highlight(), strna(loader), ansi_normal());

                for (i = 0; i < ELEMENTSOF(flags); i++) {

                        if (i == 0)
                                printf("     Features: ");
                        else
                                printf("               ");

                        if (FLAGS_SET(loader_features, flags[i].flag))
                                printf("%s%s%s %s\n", ansi_highlight_green(), special_glyph(SPECIAL_GLYPH_CHECK_MARK), ansi_normal(), flags[i].name);
                        else
                                printf("%s%s%s %s\n", ansi_highlight_red(), special_glyph(SPECIAL_GLYPH_CROSS_MARK), ansi_normal(), flags[i].name);
                }

                if (stub)
                        printf("         Stub: %s\n", stub);
                if (!sd_id128_is_null(loader_part_uuid))
                        printf("          ESP: /dev/disk/by-partuuid/%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x\n",
                               SD_ID128_FORMAT_VAL(loader_part_uuid));
                else
                        printf("          ESP: n/a\n");
                printf("         File: %s%s\n", special_glyph(SPECIAL_GLYPH_TREE_RIGHT), strna(loader_path));
                printf("\n");
        } else
                printf("System:\n    Not booted with EFI\n\n");

        if (arg_path) {
                k = status_binaries(arg_path, uuid);
                if (k < 0)
                        r = k;
        }

        if (is_efi_boot()) {
                k = status_variables();
                if (k < 0)
                        r = k;
        }

        if (arg_path) {
                k = status_entries(arg_path, uuid);
                if (k < 0)
                        r = k;
        }

        return r;
}

static int verb_list(int argc, char *argv[], void *userdata) {
        _cleanup_(boot_config_free) BootConfig config = {};
        _cleanup_free_ char **found_by_loader = NULL;
        sd_id128_t uuid = SD_ID128_NULL;
        int r;

        /* If we lack privileges we invoke find_esp_and_warn() in "unprivileged mode" here, which does two things: turn
         * off logging about access errors and turn off potentially privileged device probing. Here we're interested in
         * the latter but not the former, hence request the mode, and log about EACCES. */

        r = acquire_esp(geteuid() != 0, NULL, NULL, NULL, &uuid);
        if (r == -EACCES) /* We really need the ESP path for this call, hence also log about access errors */
                return log_error_errno(r, "Failed to determine ESP: %m");
        if (r < 0)
                return r;

        r = boot_entries_load_config(arg_path, &config);
        if (r < 0)
                return r;

        r = efi_loader_get_entries(&found_by_loader);
        if (r < 0 && !IN_SET(r, -ENOENT, -EOPNOTSUPP))
                log_debug_errno(r, "Failed to acquire boot loader discovered entries: %m");

        if (config.n_entries == 0)
                log_info("No boot loader entries found.");
        else {
                size_t n;

                (void) pager_open(arg_pager_flags);

                printf("Boot Loader Entries:\n");

                for (n = 0; n < config.n_entries; n++) {
                        r = boot_entry_show(config.entries + n, n == (size_t) config.default_entry);
                        if (r < 0)
                                return r;

                        puts("");

                        strv_remove(found_by_loader, config.entries[n].id);
                }
        }

        if (!strv_isempty(found_by_loader)) {
                char **i;

                printf("Automatic/Other Entries Found by Boot Loader:\n\n");

                STRV_FOREACH(i, found_by_loader)
                        puts(*i);
        }

        return 0;
}

static int sync_esp(void) {
        _cleanup_close_ int fd = -1;

        if (!arg_path)
                return 0;

        fd = open(arg_path, O_CLOEXEC|O_DIRECTORY|O_RDONLY);
        if (fd < 0)
                return log_error_errno(errno, "Couldn't open ESP '%s' for synchronization: %m", arg_path);

        if (syncfs(fd) < 0)
                return log_error_errno(errno, "Failed to synchronize the ESP '%s': %m", arg_path);

        return 1;
}

static int verb_install(int argc, char *argv[], void *userdata) {

        sd_id128_t uuid = SD_ID128_NULL;
        uint64_t pstart = 0, psize = 0;
        uint32_t part = 0;
        bool install;
        int r;

        r = acquire_esp(false, &part, &pstart, &psize, &uuid);
        if (r < 0)
                return r;

        install = streq(argv[0], "install");

        RUN_WITH_UMASK(0002) {
                r = install_binaries(arg_path, install);
                if (r < 0)
                        return r;

                if (install) {
                        r = install_loader_config(arg_path);
                        if (r < 0)
                                return r;
                }
        }

        (void) sync_esp();

        if (arg_touch_variables)
                r = install_variables(arg_path,
                                      part, pstart, psize, uuid,
                                      "/EFI/systemd/systemd-boot" EFI_MACHINE_TYPE_NAME ".efi",
                                      install);

        return r;
}

static int verb_remove(int argc, char *argv[], void *userdata) {
        sd_id128_t uuid = SD_ID128_NULL;
        int r;

        r = acquire_esp(false, NULL, NULL, NULL, &uuid);
        if (r < 0)
                return r;

        r = remove_binaries(arg_path);

        (void) sync_esp();

        if (arg_touch_variables) {
                int q;

                q = remove_variables(uuid, "/EFI/systemd/systemd-boot" EFI_MACHINE_TYPE_NAME ".efi", true);
                if (q < 0 && r == 0)
                        r = q;
        }

        return r;
}

static int verb_set_default(int argc, char *argv[], void *userdata) {
        const char *name;
        int r;

        if (!is_efi_boot())
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "Not booted with UEFI.");

        if (access("/sys/firmware/efi/efivars/LoaderInfo-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f", F_OK) < 0) {
                if (errno == ENOENT) {
                        log_error_errno(errno, "Not booted with a supported boot loader.");
                        return -EOPNOTSUPP;
                }

                return log_error_errno(errno, "Failed to detect whether boot loader supports '%s' operation: %m", argv[0]);
        }

        if (detect_container() > 0)
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "'%s' operation not supported in a container.",
                                       argv[0]);

        if (!arg_touch_variables)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "'%s' operation cannot be combined with --touch-variables=no.",
                                       argv[0]);

        name = streq(argv[0], "set-default") ? "LoaderEntryDefault" : "LoaderEntryOneShot";

        if (isempty(argv[1])) {
                r = efi_set_variable(EFI_VENDOR_LOADER, name, NULL, 0);
                if (r < 0 && r != -ENOENT)
                        return log_error_errno(r, "Failed to remove EFI variale: %m");
        } else {
                _cleanup_free_ char16_t *encoded = NULL;

                encoded = utf8_to_utf16(argv[1], strlen(argv[1]));
                if (!encoded)
                        return log_oom();

                r = efi_set_variable(EFI_VENDOR_LOADER, name, encoded, char16_strlen(encoded) * 2 + 2);
                if (r < 0)
                        return log_error_errno(r, "Failed to update EFI variable: %m");
        }

        return 0;
}

static int bootctl_main(int argc, char *argv[]) {

        static const Verb verbs[] = {
                { "help",        VERB_ANY, VERB_ANY, 0,                 help             },
                { "status",      VERB_ANY, 1,        VERB_DEFAULT,      verb_status      },
                { "install",     VERB_ANY, 1,        VERB_MUST_BE_ROOT, verb_install     },
                { "update",      VERB_ANY, 1,        VERB_MUST_BE_ROOT, verb_install     },
                { "remove",      VERB_ANY, 1,        VERB_MUST_BE_ROOT, verb_remove      },
                { "list",        VERB_ANY, 1,        0,                 verb_list        },
                { "set-default", 2,        2,        VERB_MUST_BE_ROOT, verb_set_default },
                { "set-oneshot", 2,        2,        VERB_MUST_BE_ROOT, verb_set_default },
                {}
        };

        return dispatch_verb(argc, argv, verbs, NULL);
}

static int run(int argc, char *argv[]) {
        int r;

        log_parse_environment();
        log_open();

        /* If we run in a container, automatically turn of EFI file system access */
        if (detect_container() > 0)
                arg_touch_variables = false;

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        return bootctl_main(argc, argv);
}

DEFINE_MAIN_FUNCTION(run);
