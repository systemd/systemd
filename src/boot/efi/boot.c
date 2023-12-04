/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bcd.h"
#include "bootspec-fundamental.h"
#include "console.h"
#include "device-path-util.h"
#include "devicetree.h"
#include "drivers.h"
#include "efivars-fundamental.h"
#include "graphics.h"
#include "initrd.h"
#include "linux.h"
#include "macro-fundamental.h"
#include "measure.h"
#include "part-discovery.h"
#include "pe.h"
#include "proto/block-io.h"
#include "proto/device-path.h"
#include "proto/simple-text-io.h"
#include "random-seed.h"
#include "sbat.h"
#include "secure-boot.h"
#include "shim.h"
#include "ticks.h"
#include "tpm2-pcr.h"
#include "util.h"
#include "version.h"
#include "vmm.h"

/* Magic string for recognizing our own binaries */
#define SD_MAGIC "#### LoaderInfo: systemd-boot " GIT_VERSION " ####"
DECLARE_NOALLOC_SECTION(".sdmagic", SD_MAGIC);

/* Makes systemd-boot available from \EFI\Linux\ for testing purposes. */
DECLARE_NOALLOC_SECTION(
                ".osrel",
                "ID=systemd-boot\n"
                "VERSION=\"" GIT_VERSION "\"\n"
                "NAME=\"systemd-boot " GIT_VERSION "\"\n");

DECLARE_SBAT(SBAT_BOOT_SECTION_TEXT);

typedef enum LoaderType {
        LOADER_UNDEFINED,
        LOADER_AUTO,
        LOADER_EFI,
        LOADER_LINUX,         /* Boot loader spec type #1 entries */
        LOADER_UNIFIED_LINUX, /* Boot loader spec type #2 entries */
        LOADER_SECURE_BOOT_KEYS,
        _LOADER_TYPE_MAX,
} LoaderType;

typedef struct {
        char16_t *id;         /* The unique identifier for this entry (typically the filename of the file defining the entry) */
        char16_t *title_show; /* The string to actually display (this is made unique before showing) */
        char16_t *title;      /* The raw (human readable) title string of the entry (not necessarily unique) */
        char16_t *sort_key;   /* The string to use as primary sort key, usually ID= from os-release, possibly suffixed */
        char16_t *version;    /* The raw (human readable) version string of the entry */
        char16_t *machine_id;
        EFI_HANDLE *device;
        LoaderType type;
        char16_t *loader;
        char16_t *devicetree;
        char16_t *options;
        bool options_implied; /* If true, these options are implied if we invoke the PE binary without any parameters (as in: UKI). If false we must specify these options explicitly. */
        char16_t **initrd;
        char16_t key;
        EFI_STATUS (*call)(void);
        int tries_done;
        int tries_left;
        char16_t *path;
        char16_t *current_name;
        char16_t *next_name;
} BootEntry;

typedef struct {
        BootEntry **entries;
        size_t n_entries;
        size_t idx_default;
        size_t idx_default_efivar;
        uint64_t timeout_sec; /* Actual timeout used (efi_main() override > efivar > config). */
        uint64_t timeout_sec_config;
        uint64_t timeout_sec_efivar;
        char16_t *entry_default_config;
        char16_t *entry_default_efivar;
        char16_t *entry_oneshot;
        char16_t *entry_saved;
        bool editor;
        bool auto_entries;
        bool auto_firmware;
        bool auto_poweroff;
        bool auto_reboot;
        bool reboot_for_bitlocker;
        secure_boot_enroll secure_boot_enroll;
        bool force_menu;
        bool use_saved_entry;
        bool use_saved_entry_efivar;
        bool beep;
        int64_t console_mode;
        int64_t console_mode_efivar;
} Config;

/* These values have been chosen so that the transitions the user sees could employ unsigned over-/underflow
 * like this:
 * efivar unset ↔ force menu ↔ no timeout/skip menu ↔ 1 s ↔ 2 s ↔ …
 *
 * Note: all the values below are ABI, so they are not allowed to change. The bootctl tool sets the numerical
 * value of TIMEOUT_MENU_FORCE and TIMEOUT_MENU_HIDDEN, instead of the string for compatibility reasons.
 *
 * The other values may be set by systemd-boot itself and changing those will lead to functional regression
 * when new version of systemd-boot is installed.
 *
 * All the 64bit values are not ABI and will never be written to an efi variable.
 */
enum {
        TIMEOUT_MIN           = 1,
        TIMEOUT_MAX           = UINT32_MAX - 2U,
        TIMEOUT_UNSET         = UINT32_MAX - 1U,
        TIMEOUT_MENU_FORCE    = UINT32_MAX,
        TIMEOUT_MENU_HIDDEN   = 0,
        TIMEOUT_TYPE_MAX      = UINT32_MAX,
        TIMEOUT_MENU_DISABLED = (uint64_t)UINT32_MAX + 1U,
        TIMEOUT_TYPE_MAX64    = UINT64_MAX,
};

enum {
        IDX_MAX = INT16_MAX,
        IDX_INVALID,
};

static void cursor_left(size_t *cursor, size_t *first) {
        assert(cursor);
        assert(first);

        if ((*cursor) > 0)
                (*cursor)--;
        else if ((*first) > 0)
                (*first)--;
}

static void cursor_right(size_t *cursor, size_t *first, size_t x_max, size_t len) {
        assert(cursor);
        assert(first);

        if ((*cursor)+1 < x_max)
                (*cursor)++;
        else if ((*first) + (*cursor) < len)
                (*first)++;
}

static bool line_edit(char16_t **line_in, size_t x_max, size_t y_pos) {
        _cleanup_free_ char16_t *line = NULL, *print = NULL;
        size_t size, len, first = 0, cursor = 0, clear = 0;

        /* Edit the line and return true if it should be executed, false if not. */

        assert(line_in);

        len = strlen16(*line_in);
        size = len + 1024;
        line = xnew(char16_t, size);
        print = xnew(char16_t, x_max + 1);
        strcpy16(line, strempty(*line_in));

        for (;;) {
                EFI_STATUS err;
                uint64_t key;
                size_t j, cursor_color = EFI_TEXT_ATTR_SWAP(COLOR_EDIT);

                j = MIN(len - first, x_max);
                memcpy(print, line + first, j * sizeof(char16_t));
                while (clear > 0 && j < x_max) {
                        clear--;
                        print[j++] = ' ';
                }
                print[j] = '\0';

                /* See comment at edit_line() call site for why we start at 1. */
                print_at(1, y_pos, COLOR_EDIT, print);

                if (!print[cursor])
                        print[cursor] = ' ';
                print[cursor+1] = '\0';
                do {
                        print_at(cursor + 1, y_pos, cursor_color, print + cursor);
                        cursor_color = EFI_TEXT_ATTR_SWAP(cursor_color);

                        err = console_key_read(&key, 750 * 1000);
                        if (!IN_SET(err, EFI_SUCCESS, EFI_TIMEOUT, EFI_NOT_READY))
                                return false;

                        print_at(cursor + 1, y_pos, COLOR_EDIT, print + cursor);
                } while (err != EFI_SUCCESS);

                switch (key) {
                case KEYPRESS(0, SCAN_ESC, 0):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, 'c'):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, 'g'):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, CHAR_CTRL('c')):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, CHAR_CTRL('g')):
                        return false;

                case KEYPRESS(0, SCAN_HOME, 0):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, 'a'):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, CHAR_CTRL('a')):
                        /* beginning-of-line */
                        cursor = 0;
                        first = 0;
                        continue;

                case KEYPRESS(0, SCAN_END, 0):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, 'e'):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, CHAR_CTRL('e')):
                        /* end-of-line */
                        cursor = len - first;
                        if (cursor+1 >= x_max) {
                                cursor = x_max-1;
                                first = len - (x_max-1);
                        }
                        continue;

                case KEYPRESS(0, SCAN_DOWN, 0):
                case KEYPRESS(EFI_ALT_PRESSED, 0, 'f'):
                case KEYPRESS(EFI_CONTROL_PRESSED, SCAN_RIGHT, 0):
                        /* forward-word */
                        while (line[first + cursor] == ' ')
                                cursor_right(&cursor, &first, x_max, len);
                        while (line[first + cursor] && line[first + cursor] != ' ')
                                cursor_right(&cursor, &first, x_max, len);
                        continue;

                case KEYPRESS(0, SCAN_UP, 0):
                case KEYPRESS(EFI_ALT_PRESSED, 0, 'b'):
                case KEYPRESS(EFI_CONTROL_PRESSED, SCAN_LEFT, 0):
                        /* backward-word */
                        if ((first + cursor) > 0 && line[first + cursor-1] == ' ') {
                                cursor_left(&cursor, &first);
                                while ((first + cursor) > 0 && line[first + cursor] == ' ')
                                        cursor_left(&cursor, &first);
                        }
                        while ((first + cursor) > 0 && line[first + cursor-1] != ' ')
                                cursor_left(&cursor, &first);
                        continue;

                case KEYPRESS(0, SCAN_RIGHT, 0):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, 'f'):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, CHAR_CTRL('f')):
                        /* forward-char */
                        if (first + cursor == len)
                                continue;
                        cursor_right(&cursor, &first, x_max, len);
                        continue;

                case KEYPRESS(0, SCAN_LEFT, 0):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, 'b'):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, CHAR_CTRL('b')):
                        /* backward-char */
                        cursor_left(&cursor, &first);
                        continue;

                case KEYPRESS(EFI_CONTROL_PRESSED, SCAN_DELETE, 0):
                case KEYPRESS(EFI_ALT_PRESSED, 0, 'd'):
                        /* kill-word */
                        clear = 0;

                        size_t k;
                        for (k = first + cursor; k < len && line[k] == ' '; k++)
                                clear++;
                        for (; k < len && line[k] != ' '; k++)
                                clear++;

                        for (size_t i = first + cursor; i + clear < len; i++)
                                line[i] = line[i + clear];
                        len -= clear;
                        line[len] = '\0';
                        continue;

                case KEYPRESS(EFI_CONTROL_PRESSED, 0, 'w'):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, CHAR_CTRL('w')):
                case KEYPRESS(EFI_ALT_PRESSED, 0, '\b'):
                        /* backward-kill-word */
                        clear = 0;
                        if ((first + cursor) > 0 && line[first + cursor-1] == ' ') {
                                cursor_left(&cursor, &first);
                                clear++;
                                while ((first + cursor) > 0 && line[first + cursor] == ' ') {
                                        cursor_left(&cursor, &first);
                                        clear++;
                                }
                        }
                        while ((first + cursor) > 0 && line[first + cursor-1] != ' ') {
                                cursor_left(&cursor, &first);
                                clear++;
                        }

                        for (size_t i = first + cursor; i + clear < len; i++)
                                line[i] = line[i + clear];
                        len -= clear;
                        line[len] = '\0';
                        continue;

                case KEYPRESS(0, SCAN_DELETE, 0):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, 'd'):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, CHAR_CTRL('d')):
                        if (len == 0)
                                continue;
                        if (first + cursor == len)
                                continue;
                        for (size_t i = first + cursor; i < len; i++)
                                line[i] = line[i+1];
                        clear = 1;
                        len--;
                        continue;

                case KEYPRESS(EFI_CONTROL_PRESSED, 0, 'k'):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, CHAR_CTRL('k')):
                        /* kill-line */
                        line[first + cursor] = '\0';
                        clear = len - (first + cursor);
                        len = first + cursor;
                        continue;

                case KEYPRESS(0, 0, '\n'):
                case KEYPRESS(0, 0, '\r'):
                case KEYPRESS(0, SCAN_F3, 0): /* EZpad Mini 4s firmware sends malformed events */
                case KEYPRESS(0, SCAN_F3, '\r'): /* Teclast X98+ II firmware sends malformed events */
                        if (!streq16(line, *line_in)) {
                                free(*line_in);
                                *line_in = TAKE_PTR(line);
                        }
                        return true;

                case KEYPRESS(0, 0, '\b'):
                        if (len == 0)
                                continue;
                        if (first == 0 && cursor == 0)
                                continue;
                        for (size_t i = first + cursor-1; i < len; i++)
                                line[i] = line[i+1];
                        clear = 1;
                        len--;
                        if (cursor > 0)
                                cursor--;
                        if (cursor > 0 || first == 0)
                                continue;
                        /* show full line if it fits */
                        if (len < x_max) {
                                cursor = first;
                                first = 0;
                                continue;
                        }
                        /* jump left to see what we delete */
                        if (first > 10) {
                                first -= 10;
                                cursor = 10;
                        } else {
                                cursor = first;
                                first = 0;
                        }
                        continue;

                case KEYPRESS(0, 0, ' ') ... KEYPRESS(0, 0, '~'):
                case KEYPRESS(0, 0, 0x80) ... KEYPRESS(0, 0, 0xffff):
                        if (len+1 == size)
                                continue;
                        for (size_t i = len; i > first + cursor; i--)
                                line[i] = line[i-1];
                        line[first + cursor] = KEYCHAR(key);
                        len++;
                        line[len] = '\0';
                        if (cursor+1 < x_max)
                                cursor++;
                        else if (first + cursor < len)
                                first++;
                        continue;
                }
        }
}

static size_t entry_lookup_key(Config *config, size_t start, char16_t key) {
        assert(config);

        if (key == 0)
                return IDX_INVALID;

        /* select entry by number key */
        if (key >= '1' && key <= '9') {
                size_t i = key - '0';
                if (i > config->n_entries)
                        i = config->n_entries;
                return i-1;
        }

        /* find matching key in boot entries */
        for (size_t i = start; i < config->n_entries; i++)
                if (config->entries[i]->key == key)
                        return i;

        for (size_t i = 0; i < start; i++)
                if (config->entries[i]->key == key)
                        return i;

        return IDX_INVALID;
}

static char16_t* update_timeout_efivar(Config *config, bool inc) {
        assert(config);

        switch (config->timeout_sec) {
        case TIMEOUT_MAX:
                config->timeout_sec = inc ? TIMEOUT_MAX : config->timeout_sec - 1;
                break;
        case TIMEOUT_UNSET:
                config->timeout_sec = inc ? TIMEOUT_MENU_FORCE : TIMEOUT_UNSET;
                break;
        case TIMEOUT_MENU_DISABLED:
                config->timeout_sec = inc ? TIMEOUT_MIN : TIMEOUT_MENU_FORCE;
                break;
        case TIMEOUT_MENU_FORCE:
                config->timeout_sec = inc ? TIMEOUT_MENU_HIDDEN : TIMEOUT_MENU_FORCE;
                break;
        case TIMEOUT_MENU_HIDDEN:
                config->timeout_sec = inc ? TIMEOUT_MIN : TIMEOUT_MENU_FORCE;
                break;
        default:
                config->timeout_sec = config->timeout_sec + (inc ? 1 : -1);
        }

        config->timeout_sec_efivar = config->timeout_sec;

        switch (config->timeout_sec) {
        case TIMEOUT_UNSET:
                return xstrdup16(u"Menu timeout defined by configuration file.");
        case TIMEOUT_MENU_DISABLED:
                assert_not_reached();
        case TIMEOUT_MENU_FORCE:
                return xstrdup16(u"Timeout disabled, menu will always be shown.");
        case TIMEOUT_MENU_HIDDEN:
                return xstrdup16(u"Menu hidden. Hold down key at bootup to show menu.");
        default:
                return xasprintf("Menu timeout set to %u s.", (uint32_t)config->timeout_sec_efivar);
        }
}

static bool unicode_supported(void) {
        static int cache = -1;

        if (cache < 0)
                /* Basic unicode box drawing support is mandated by the spec, but it does
                 * not hurt to make sure it works. */
                cache = ST->ConOut->TestString(ST->ConOut, (char16_t *) u"─") == EFI_SUCCESS;

        return cache;
}

static bool ps_continue(void) {
        const char16_t *sep = unicode_supported() ? u"───" : u"---";
        printf("\n%ls Press any key to continue, ESC or q to quit. %ls\n\n", sep, sep);

        uint64_t key;
        return console_key_read(&key, UINT64_MAX) == EFI_SUCCESS &&
                        !IN_SET(key, KEYPRESS(0, SCAN_ESC, 0), KEYPRESS(0, 0, 'q'), KEYPRESS(0, 0, 'Q'));
}

static void print_timeout_status(const char *label, uint64_t t) {
        switch (t) {
        case TIMEOUT_UNSET:
                return;
        case TIMEOUT_MENU_DISABLED:
                return (void) printf("%s: menu-disabled\n", label);
        case TIMEOUT_MENU_FORCE:
                return (void) printf("%s: menu-force\n", label);
        case TIMEOUT_MENU_HIDDEN:
                return (void) printf("%s: menu-hidden\n", label);
        default:
                return (void) printf("%s: %u s\n", label, (uint32_t)t);
        }
}

static void print_status(Config *config, char16_t *loaded_image_path) {
        size_t x_max, y_max;
        uint32_t screen_width = 0, screen_height = 0;
        SecureBootMode secure;
        _cleanup_free_ char16_t *device_part_uuid = NULL;

        assert(config);

        clear_screen(COLOR_NORMAL);
        console_query_mode(&x_max, &y_max);
        query_screen_resolution(&screen_width, &screen_height);

        secure = secure_boot_mode();
        (void) efivar_get(MAKE_GUID_PTR(LOADER), u"LoaderDevicePartUUID", &device_part_uuid);

        printf("  systemd-boot version: " GIT_VERSION "\n");
        if (loaded_image_path)
                printf("          loaded image: %ls\n", loaded_image_path);
        if (device_part_uuid)
                printf(" loader partition UUID: %ls\n", device_part_uuid);
        printf("          architecture: " EFI_MACHINE_TYPE_NAME "\n");
        printf("    UEFI specification: %u.%02u\n", ST->Hdr.Revision >> 16, ST->Hdr.Revision & 0xffff);
        printf("       firmware vendor: %ls\n", ST->FirmwareVendor);
        printf("      firmware version: %u.%02u\n", ST->FirmwareRevision >> 16, ST->FirmwareRevision & 0xffff);
        printf("        OS indications: %#" PRIx64 "\n", get_os_indications_supported());
        printf("           secure boot: %ls (%ls)\n",
                        yes_no(IN_SET(secure, SECURE_BOOT_USER, SECURE_BOOT_DEPLOYED)),
                        secure_boot_mode_to_string(secure));
        printf("                  shim: %ls\n", yes_no(shim_loaded()));
        printf("                   TPM: %ls\n", yes_no(tpm_present()));
        printf("          console mode: %i/%" PRIi64 " (%zux%zu @%ux%u)\n",
                        ST->ConOut->Mode->Mode, ST->ConOut->Mode->MaxMode - INT64_C(1),
                        x_max, y_max, screen_width, screen_height);

        if (!ps_continue())
                return;

        print_timeout_status("      timeout (config)", config->timeout_sec_config);
        print_timeout_status("     timeout (EFI var)", config->timeout_sec_efivar);

        if (config->entry_default_config)
                printf("      default (config): %ls\n", config->entry_default_config);
        if (config->entry_default_efivar)
                printf("     default (EFI var): %ls\n", config->entry_default_efivar);
        if (config->entry_oneshot)
                printf("    default (one-shot): %ls\n", config->entry_oneshot);
        if (config->entry_saved)
                printf("           saved entry: %ls\n", config->entry_saved);
        printf("                editor: %ls\n", yes_no(config->editor));
        printf("          auto-entries: %ls\n", yes_no(config->auto_entries));
        printf("         auto-firmware: %ls\n", yes_no(config->auto_firmware));
        printf("         auto-poweroff: %ls\n", yes_no(config->auto_poweroff));
        printf("           auto-reboot: %ls\n", yes_no(config->auto_reboot));
        printf("                  beep: %ls\n", yes_no(config->beep));
        printf("  reboot-for-bitlocker: %ls\n", yes_no(config->reboot_for_bitlocker));

        switch (config->secure_boot_enroll) {
        case ENROLL_OFF:
                printf("    secure-boot-enroll: off\n");
                break;
        case ENROLL_MANUAL:
                printf("    secure-boot-enroll: manual\n");
                break;
        case ENROLL_IF_SAFE:
                printf("    secure-boot-enroll: if-safe\n");
                break;
        case ENROLL_FORCE:
                printf("    secure-boot-enroll: force\n");
                break;
        default:
                assert_not_reached();
        }

        switch (config->console_mode) {
        case CONSOLE_MODE_AUTO:
                printf(" console-mode (config): auto\n");
                break;
        case CONSOLE_MODE_KEEP:
                printf(" console-mode (config): keep\n");
                break;
        case CONSOLE_MODE_FIRMWARE_MAX:
                printf(" console-mode (config): max\n");
                break;
        default:
                printf(" console-mode (config): %" PRIi64 "\n", config->console_mode);
                break;
        }

        /* EFI var console mode is always a concrete value or unset. */
        if (config->console_mode_efivar != CONSOLE_MODE_KEEP)
                printf("console-mode (EFI var): %" PRIi64 "\n", config->console_mode_efivar);

        if (!ps_continue())
                return;

        for (size_t i = 0; i < config->n_entries; i++) {
                BootEntry *entry = config->entries[i];
                EFI_DEVICE_PATH *dp = NULL;
                _cleanup_free_ char16_t *dp_str = NULL;

                if (entry->device &&
                    BS->HandleProtocol(entry->device, MAKE_GUID_PTR(EFI_DEVICE_PATH_PROTOCOL), (void **) &dp) ==
                                    EFI_SUCCESS)
                        (void) device_path_to_str(dp, &dp_str);

                printf("    boot entry: %zu/%zu\n", i + 1, config->n_entries);
                printf("            id: %ls\n", entry->id);
                if (entry->title)
                        printf("         title: %ls\n", entry->title);
                if (entry->title_show && !streq16(entry->title, entry->title_show))
                        printf("    title show: %ls\n", entry->title_show);
                if (entry->sort_key)
                        printf("      sort key: %ls\n", entry->sort_key);
                if (entry->version)
                        printf("       version: %ls\n", entry->version);
                if (entry->machine_id)
                        printf("    machine-id: %ls\n", entry->machine_id);
                if (dp_str)
                        printf("        device: %ls\n", dp_str);
                if (entry->loader)
                        printf("        loader: %ls\n", entry->loader);
                STRV_FOREACH(initrd, entry->initrd)
                        printf("        initrd: %ls\n", *initrd);
                if (entry->devicetree)
                        printf("    devicetree: %ls\n", entry->devicetree);
                if (entry->options)
                        printf("       options: %ls\n", entry->options);
                printf(" internal call: %ls\n", yes_no(!!entry->call));

                printf("counting boots: %ls\n", yes_no(entry->tries_left >= 0));
                if (entry->tries_left >= 0) {
                        printf("         tries: %i left, %i done\n", entry->tries_left, entry->tries_done);
                        printf("  current path: %ls\\%ls\n", entry->path, entry->current_name);
                        printf("     next path: %ls\\%ls\n", entry->path, entry->next_name);
                }

                if (!ps_continue())
                        return;
        }
}

static EFI_STATUS set_reboot_into_firmware(void) {
        uint64_t osind = 0;
        EFI_STATUS err;

        (void) efivar_get_uint64_le(MAKE_GUID_PTR(EFI_GLOBAL_VARIABLE), u"OsIndications", &osind);
        osind |= EFI_OS_INDICATIONS_BOOT_TO_FW_UI;

        err = efivar_set_uint64_le(MAKE_GUID_PTR(EFI_GLOBAL_VARIABLE), u"OsIndications", osind, EFI_VARIABLE_NON_VOLATILE);
        if (err != EFI_SUCCESS)
                log_error_status(err, "Error setting OsIndications: %m");
        return err;
}

_noreturn_ static EFI_STATUS poweroff_system(void) {
        RT->ResetSystem(EfiResetShutdown, EFI_SUCCESS, 0, NULL);
        assert_not_reached();
}

_noreturn_ static EFI_STATUS reboot_system(void) {
        RT->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);
        assert_not_reached();
}

static EFI_STATUS reboot_into_firmware(void) {
        EFI_STATUS err;

        err = set_reboot_into_firmware();
        if (err != EFI_SUCCESS)
                return err;

        return reboot_system();
}

static bool menu_run(
                Config *config,
                BootEntry **chosen_entry,
                char16_t *loaded_image_path) {

        assert(config);
        assert(chosen_entry);

        EFI_STATUS err;
        size_t visible_max = 0;
        size_t idx_highlight = config->idx_default, idx_highlight_prev = 0;
        size_t idx, idx_first = 0, idx_last = 0;
        bool new_mode = true, clear = true;
        bool refresh = true, highlight = false;
        size_t x_start = 0, y_start = 0, y_status = 0, x_max, y_max;
        _cleanup_(strv_freep) char16_t **lines = NULL;
        _cleanup_free_ char16_t *clearline = NULL, *separator = NULL, *status = NULL;
        uint64_t timeout_efivar_saved = config->timeout_sec_efivar;
        uint32_t timeout_remain = config->timeout_sec == TIMEOUT_MENU_FORCE ? 0 : config->timeout_sec;
        int64_t console_mode_initial = ST->ConOut->Mode->Mode, console_mode_efivar_saved = config->console_mode_efivar;
        size_t default_efivar_saved = config->idx_default_efivar;

        enum {
                ACTION_CONTINUE,        /* Continue with loop over user input */
                ACTION_FIRMWARE_SETUP,  /* Ask for confirmation and reboot into firmware setup */
                ACTION_POWEROFF,        /* Power off the machine */
                ACTION_REBOOT,          /* Reboot the machine */
                ACTION_RUN,             /* Execute a boot entry */
                ACTION_QUIT,            /* Return to the firmware */
        } action = ACTION_CONTINUE;

        graphics_mode(false);
        ST->ConIn->Reset(ST->ConIn, false);
        ST->ConOut->EnableCursor(ST->ConOut, false);

        /* draw a single character to make ClearScreen work on some firmware */
        ST->ConOut->OutputString(ST->ConOut, (char16_t *) u" ");

        err = console_set_mode(config->console_mode_efivar != CONSOLE_MODE_KEEP ?
                               config->console_mode_efivar : config->console_mode);
        if (err != EFI_SUCCESS) {
                clear_screen(COLOR_NORMAL);
                log_error_status(err, "Error switching console mode: %m");
        }

        size_t line_width = 0, entry_padding = 3;
        while (IN_SET(action, ACTION_CONTINUE, ACTION_FIRMWARE_SETUP)) {
                uint64_t key;

                if (new_mode) {
                        console_query_mode(&x_max, &y_max);

                        /* account for padding+status */
                        visible_max = y_max - 2;

                        /* Drawing entries starts at idx_first until idx_last. We want to make
                        * sure that idx_highlight is centered, but not if we are close to the
                        * beginning/end of the entry list. Otherwise we would have a half-empty
                        * screen. */
                        if (config->n_entries <= visible_max || idx_highlight <= visible_max / 2)
                                idx_first = 0;
                        else if (idx_highlight >= config->n_entries - (visible_max / 2))
                                idx_first = config->n_entries - visible_max;
                        else
                                idx_first = idx_highlight - (visible_max / 2);
                        idx_last = idx_first + visible_max - 1;

                        /* length of the longest entry */
                        line_width = 0;
                        for (size_t i = 0; i < config->n_entries; i++)
                                line_width = MAX(line_width, strlen16(config->entries[i]->title_show));
                        line_width = MIN(line_width + 2 * entry_padding, x_max);

                        /* offsets to center the entries on the screen */
                        x_start = (x_max - (line_width)) / 2;
                        if (config->n_entries < visible_max)
                                y_start = ((visible_max - config->n_entries) / 2) + 1;
                        else
                                y_start = 0;

                        /* Put status line after the entry list, but give it some breathing room. */
                        y_status = MIN(y_start + MIN(visible_max, config->n_entries) + 1, y_max - 1);

                        lines = strv_free(lines);
                        clearline = mfree(clearline);
                        separator = mfree(separator);

                        /* menu entries title lines */
                        lines = xnew(char16_t *, config->n_entries + 1);

                        for (size_t i = 0; i < config->n_entries; i++) {
                                size_t j, padding;

                                lines[i] = xnew(char16_t, line_width + 1);
                                padding = (line_width - MIN(strlen16(config->entries[i]->title_show), line_width)) / 2;

                                for (j = 0; j < padding; j++)
                                        lines[i][j] = ' ';

                                for (size_t k = 0; config->entries[i]->title_show[k] != '\0' && j < line_width; j++, k++)
                                        lines[i][j] = config->entries[i]->title_show[k];

                                for (; j < line_width; j++)
                                        lines[i][j] = ' ';
                                lines[i][line_width] = '\0';
                        }
                        lines[config->n_entries] = NULL;

                        clearline = xnew(char16_t, x_max + 1);
                        separator = xnew(char16_t, x_max + 1);
                        for (size_t i = 0; i < x_max; i++) {
                                clearline[i] = ' ';
                                separator[i] = unicode_supported() ? L'─' : L'-';
                        }
                        clearline[x_max] = 0;
                        separator[x_max] = 0;

                        new_mode = false;
                        clear = true;
                }

                if (clear) {
                        clear_screen(COLOR_NORMAL);
                        clear = false;
                        refresh = true;
                }

                if (refresh) {
                        for (size_t i = idx_first; i <= idx_last && i < config->n_entries; i++) {
                                print_at(x_start, y_start + i - idx_first,
                                         i == idx_highlight ? COLOR_HIGHLIGHT : COLOR_ENTRY,
                                         lines[i]);
                                if (i == config->idx_default_efivar)
                                        print_at(x_start,
                                                 y_start + i - idx_first,
                                                 i == idx_highlight ? COLOR_HIGHLIGHT : COLOR_ENTRY,
                                                 unicode_supported() ? u" ►" : u"=>");
                        }
                        refresh = false;
                } else if (highlight) {
                        print_at(x_start, y_start + idx_highlight_prev - idx_first, COLOR_ENTRY, lines[idx_highlight_prev]);
                        print_at(x_start, y_start + idx_highlight - idx_first, COLOR_HIGHLIGHT, lines[idx_highlight]);
                        if (idx_highlight_prev == config->idx_default_efivar)
                                print_at(x_start,
                                         y_start + idx_highlight_prev - idx_first,
                                         COLOR_ENTRY,
                                         unicode_supported() ? u" ►" : u"=>");
                        if (idx_highlight == config->idx_default_efivar)
                                print_at(x_start,
                                         y_start + idx_highlight - idx_first,
                                         COLOR_HIGHLIGHT,
                                         unicode_supported() ? u" ►" : u"=>");
                        highlight = false;
                }

                if (timeout_remain > 0) {
                        free(status);
                        status = xasprintf("Boot in %u s.", timeout_remain);
                }

                if (status) {
                        /* If we draw the last char of the last line, the screen will scroll and break our
                         * input. Therefore, draw one less character then we could for the status message.
                         * Note that the same does not apply for the separator line as it will never be drawn
                         * on the last line. */
                        size_t len = strnlen16(status, x_max - 1);
                        size_t x = (x_max - len) / 2;
                        status[len] = '\0';
                        print_at(0, y_status, COLOR_NORMAL, clearline + x_max - x);
                        ST->ConOut->OutputString(ST->ConOut, status);
                        ST->ConOut->OutputString(ST->ConOut, clearline + 1 + x + len);

                        len = MIN(MAX(len, line_width) + 2 * entry_padding, x_max);
                        x = (x_max - len) / 2;
                        print_at(x, y_status - 1, COLOR_NORMAL, separator + x_max - len);
                } else {
                        print_at(0, y_status - 1, COLOR_NORMAL, clearline);
                        print_at(0, y_status, COLOR_NORMAL, clearline + 1); /* See comment above. */
                }

                /* Beep several times so that the selected entry can be distinguished. */
                if (config->beep)
                        beep(idx_highlight + 1);

                err = console_key_read(&key, timeout_remain > 0 ? 1000 * 1000 : UINT64_MAX);
                if (err == EFI_NOT_READY)
                        /* No input device returned a key, try again. This
                         * normally should not happen. */
                        continue;
                if (err == EFI_TIMEOUT) {
                        assert(timeout_remain > 0);
                        timeout_remain--;
                        if (timeout_remain == 0) {
                                action = ACTION_RUN;
                                break;
                        }

                        /* update status */
                        continue;
                }
                if (err != EFI_SUCCESS) {
                        action = ACTION_RUN;
                        break;
                }

                timeout_remain = 0;

                /* clear status after keystroke */
                status = mfree(status);

                idx_highlight_prev = idx_highlight;

                if (action == ACTION_FIRMWARE_SETUP) {
                        if (IN_SET(key, KEYPRESS(0, 0, '\r'), KEYPRESS(0, 0, '\n')) &&
                            set_reboot_into_firmware() == EFI_SUCCESS)
                                break;

                        /* Any key other than newline or a failed attempt cancel the request. */
                        action = ACTION_CONTINUE;
                        continue;
                }

                switch (key) {
                case KEYPRESS(0, SCAN_UP, 0):
                case KEYPRESS(0, 0, 'k'):
                case KEYPRESS(0, 0, 'K'):
                        if (idx_highlight > 0)
                                idx_highlight--;
                        break;

                case KEYPRESS(0, SCAN_DOWN, 0):
                case KEYPRESS(0, 0, 'j'):
                case KEYPRESS(0, 0, 'J'):
                        if (idx_highlight < config->n_entries-1)
                                idx_highlight++;
                        break;

                case KEYPRESS(0, SCAN_HOME, 0):
                case KEYPRESS(EFI_ALT_PRESSED, 0, '<'):
                        if (idx_highlight > 0) {
                                refresh = true;
                                idx_highlight = 0;
                        }
                        break;

                case KEYPRESS(0, SCAN_END, 0):
                case KEYPRESS(EFI_ALT_PRESSED, 0, '>'):
                        if (idx_highlight < config->n_entries-1) {
                                refresh = true;
                                idx_highlight = config->n_entries-1;
                        }
                        break;

                case KEYPRESS(0, SCAN_PAGE_UP, 0):
                        if (idx_highlight > visible_max)
                                idx_highlight -= visible_max;
                        else
                                idx_highlight = 0;
                        break;

                case KEYPRESS(0, SCAN_PAGE_DOWN, 0):
                        idx_highlight += visible_max;
                        if (idx_highlight > config->n_entries-1)
                                idx_highlight = config->n_entries-1;
                        break;

                case KEYPRESS(0, 0, '\n'):
                case KEYPRESS(0, 0, '\r'):
                case KEYPRESS(0, SCAN_F3, 0): /* EZpad Mini 4s firmware sends malformed events */
                case KEYPRESS(0, SCAN_F3, '\r'): /* Teclast X98+ II firmware sends malformed events */
                case KEYPRESS(0, SCAN_RIGHT, 0):
                        action = ACTION_RUN;
                        break;

                case KEYPRESS(0, SCAN_F1, 0):
                case KEYPRESS(0, 0, 'h'):
                case KEYPRESS(0, 0, 'H'):
                case KEYPRESS(0, 0, '?'):
                        /* This must stay below 80 characters! Q/v/Ctrl+l/f deliberately not advertised. */
                        status = xasprintf("(d)efault (t/T)imeout (e)dit (r/R)esolution (p)rint %s%s(h)elp",
                                           config->auto_poweroff ? "" : "(O)ff ",
                                           config->auto_reboot ? "" : "re(B)oot ");
                        break;

                case KEYPRESS(0, 0, 'Q'):
                        action = ACTION_QUIT;
                        break;

                case KEYPRESS(0, 0, 'd'):
                case KEYPRESS(0, 0, 'D'):
                        if (config->idx_default_efivar != idx_highlight) {
                                free(config->entry_default_efivar);
                                config->entry_default_efivar = xstrdup16(config->entries[idx_highlight]->id);
                                config->idx_default_efivar = idx_highlight;
                                status = xstrdup16(u"Default boot entry selected.");
                        } else {
                                config->entry_default_efivar = mfree(config->entry_default_efivar);
                                config->idx_default_efivar = IDX_INVALID;
                                status = xstrdup16(u"Default boot entry cleared.");
                        }
                        config->use_saved_entry_efivar = false;
                        refresh = true;
                        break;

                case KEYPRESS(0, 0, '-'):
                case KEYPRESS(0, 0, 'T'):
                        status = update_timeout_efivar(config, false);
                        break;

                case KEYPRESS(0, 0, '+'):
                case KEYPRESS(0, 0, 't'):
                        status = update_timeout_efivar(config, true);
                        break;

                case KEYPRESS(0, 0, 'e'):
                case KEYPRESS(0, 0, 'E'):
                        /* only the options of configured entries can be edited */
                        if (!config->editor ||
                            !IN_SET(config->entries[idx_highlight]->type, LOADER_EFI, LOADER_LINUX, LOADER_UNIFIED_LINUX)) {
                                status = xstrdup16(u"Entry does not support editing the command line.");
                                break;
                        }

                        /* Unified kernels that are signed as a whole will not accept command line options
                         * when secure boot is enabled unless there is none embedded in the image. Do not try
                         * to pretend we can edit it to only have it be ignored. */
                        if (config->entries[idx_highlight]->type == LOADER_UNIFIED_LINUX &&
                            secure_boot_enabled() &&
                            config->entries[idx_highlight]->options) {
                                status = xstrdup16(u"Entry not editable in SecureBoot mode.");
                                break;
                        }

                        /* The edit line may end up on the last line of the screen. And even though we're
                         * not telling the firmware to advance the line, it still does in this one case,
                         * causing a scroll to happen that screws with our beautiful boot loader output.
                         * Since we cannot paint the last character of the edit line, we simply start
                         * at x-offset 1 for symmetry. */
                        print_at(1, y_status, COLOR_EDIT, clearline + 2);
                        if (line_edit(&config->entries[idx_highlight]->options, x_max - 2, y_status))
                                action = ACTION_RUN;
                        print_at(1, y_status, COLOR_NORMAL, clearline + 2);

                        /* The options string was now edited, hence we have to pass it to the invoked
                         * binary. */
                        config->entries[idx_highlight]->options_implied = false;
                        break;

                case KEYPRESS(0, 0, 'v'):
                        status = xasprintf(
                                        "systemd-boot " GIT_VERSION " (" EFI_MACHINE_TYPE_NAME "), "
                                        "UEFI Specification %u.%02u, Vendor %ls %u.%02u",
                                        ST->Hdr.Revision >> 16,
                                        ST->Hdr.Revision & 0xffff,
                                        ST->FirmwareVendor,
                                        ST->FirmwareRevision >> 16,
                                        ST->FirmwareRevision & 0xffff);
                        break;

                case KEYPRESS(0, 0, 'p'):
                case KEYPRESS(0, 0, 'P'):
                        print_status(config, loaded_image_path);
                        clear = true;
                        break;

                case KEYPRESS(EFI_CONTROL_PRESSED, 0, 'l'):
                case KEYPRESS(EFI_CONTROL_PRESSED, 0, CHAR_CTRL('l')):
                case 'L': /* only uppercase, do not conflict with lower-case 'l' which picks first Linux entry */
                        clear = true;
                        break;

                case KEYPRESS(0, 0, 'r'):
                        err = console_set_mode(CONSOLE_MODE_NEXT);
                        if (err != EFI_SUCCESS)
                                status = xasprintf_status(err, "Error changing console mode: %m");
                        else {
                                config->console_mode_efivar = ST->ConOut->Mode->Mode;
                                status = xasprintf(
                                                "Console mode changed to %" PRIi64 ".",
                                                config->console_mode_efivar);
                        }
                        new_mode = true;
                        break;

                case KEYPRESS(0, 0, 'R'):
                        config->console_mode_efivar = CONSOLE_MODE_KEEP;
                        err = console_set_mode(config->console_mode == CONSOLE_MODE_KEEP ?
                                               console_mode_initial : config->console_mode);
                        if (err != EFI_SUCCESS)
                                status = xasprintf_status(err, "Error resetting console mode: %m");
                        else
                                status = xasprintf(
                                                "Console mode reset to %s default.",
                                                config->console_mode == CONSOLE_MODE_KEEP ?
                                                                "firmware" :
                                                                "configuration file");
                        new_mode = true;
                        break;

                case KEYPRESS(0, 0, 'f'):
                case KEYPRESS(0, 0, 'F'):
                case KEYPRESS(0, SCAN_F2, 0):     /* Most vendors. */
                case KEYPRESS(0, SCAN_F10, 0):    /* HP and Lenovo. */
                case KEYPRESS(0, SCAN_DELETE, 0): /* Same as F2. */
                case KEYPRESS(0, SCAN_ESC, 0):    /* HP. */
                        if (FLAGS_SET(get_os_indications_supported(), EFI_OS_INDICATIONS_BOOT_TO_FW_UI)) {
                                action = ACTION_FIRMWARE_SETUP;
                                /* Let's make sure the user really wants to do this. */
                                status = xstrdup16(u"Press Enter to reboot into firmware interface.");
                        } else
                                status = xstrdup16(u"Reboot into firmware interface not supported.");
                        break;

                case KEYPRESS(0, 0, 'O'): /* Only uppercase, so that it can't be hit so easily fat-fingered,
                                           * but still works safely over serial. */
                        action = ACTION_POWEROFF;
                        break;

                case KEYPRESS(0, 0, 'B'): /* ditto */
                        action = ACTION_REBOOT;
                        break;

                default:
                        /* jump with a hotkey directly to a matching entry */
                        idx = entry_lookup_key(config, idx_highlight+1, KEYCHAR(key));
                        if (idx == IDX_INVALID)
                                break;
                        idx_highlight = idx;
                        refresh = true;
                }

                if (idx_highlight > idx_last) {
                        idx_last = idx_highlight;
                        idx_first = 1 + idx_highlight - visible_max;
                        refresh = true;
                } else if (idx_highlight < idx_first) {
                        idx_first = idx_highlight;
                        idx_last = idx_highlight + visible_max-1;
                        refresh = true;
                }

                if (!refresh && idx_highlight != idx_highlight_prev)
                        highlight = true;
        }

        /* Update EFI vars after we left the menu to reduce NVRAM writes. */

        if (default_efivar_saved != config->idx_default_efivar)
                efivar_set(MAKE_GUID_PTR(LOADER), u"LoaderEntryDefault", config->entry_default_efivar, EFI_VARIABLE_NON_VOLATILE);

        if (console_mode_efivar_saved != config->console_mode_efivar) {
                if (config->console_mode_efivar == CONSOLE_MODE_KEEP)
                        efivar_unset(MAKE_GUID_PTR(LOADER), u"LoaderConfigConsoleMode", EFI_VARIABLE_NON_VOLATILE);
                else
                        efivar_set_uint_string(MAKE_GUID_PTR(LOADER), u"LoaderConfigConsoleMode",
                                               config->console_mode_efivar, EFI_VARIABLE_NON_VOLATILE);
        }

        if (timeout_efivar_saved != config->timeout_sec_efivar) {
                switch (config->timeout_sec_efivar) {
                case TIMEOUT_UNSET:
                        efivar_unset(MAKE_GUID_PTR(LOADER), u"LoaderConfigTimeout", EFI_VARIABLE_NON_VOLATILE);
                        break;
                case TIMEOUT_MENU_DISABLED:
                        assert_not_reached();
                case TIMEOUT_MENU_FORCE:
                        efivar_set(MAKE_GUID_PTR(LOADER), u"LoaderConfigTimeout", u"menu-force", EFI_VARIABLE_NON_VOLATILE);
                        break;
                case TIMEOUT_MENU_HIDDEN:
                        efivar_set(MAKE_GUID_PTR(LOADER), u"LoaderConfigTimeout", u"menu-hidden", EFI_VARIABLE_NON_VOLATILE);
                        break;
                default:
                        assert(config->timeout_sec_efivar < UINT32_MAX);
                        efivar_set_uint_string(MAKE_GUID_PTR(LOADER), u"LoaderConfigTimeout",
                                               config->timeout_sec_efivar, EFI_VARIABLE_NON_VOLATILE);
                }
        }

        switch (action) {
        case ACTION_CONTINUE:
                assert_not_reached();
        case ACTION_POWEROFF:
                poweroff_system();
        case ACTION_REBOOT:
        case ACTION_FIRMWARE_SETUP:
                reboot_system();
        case ACTION_RUN:
        case ACTION_QUIT:
                break;
        }

        *chosen_entry = config->entries[idx_highlight];
        clear_screen(COLOR_NORMAL);
        return action == ACTION_RUN;
}

static void config_add_entry(Config *config, BootEntry *entry) {
        assert(config);
        assert(entry);

        /* This is just for paranoia. */
        assert(config->n_entries < IDX_MAX);

        if ((config->n_entries & 15) == 0) {
                config->entries = xrealloc(
                                config->entries,
                                sizeof(void *) * config->n_entries,
                                sizeof(void *) * (config->n_entries + 16));
        }
        config->entries[config->n_entries++] = entry;
}

static BootEntry* boot_entry_free(BootEntry *entry) {
        if (!entry)
                return NULL;

        free(entry->id);
        free(entry->title_show);
        free(entry->title);
        free(entry->sort_key);
        free(entry->version);
        free(entry->machine_id);
        free(entry->loader);
        free(entry->devicetree);
        free(entry->options);
        strv_free(entry->initrd);
        free(entry->path);
        free(entry->current_name);
        free(entry->next_name);

        return mfree(entry);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(BootEntry *, boot_entry_free);

static void config_defaults_load_from_file(Config *config, char *content) {
        char *line;
        size_t pos = 0;
        char *key, *value;

        assert(config);
        assert(content);

        while ((line = line_get_key_value(content, " \t", &pos, &key, &value)))
                if (streq8(key, "timeout")) {
                        if (streq8(value, "menu-disabled"))
                                config->timeout_sec_config = TIMEOUT_MENU_DISABLED;
                        else if (streq8(value, "menu-force"))
                                config->timeout_sec_config = TIMEOUT_MENU_FORCE;
                        else if (streq8(value, "menu-hidden"))
                                config->timeout_sec_config = TIMEOUT_MENU_HIDDEN;
                        else {
                                uint64_t u;
                                if (!parse_number8(value, &u, NULL) || u > TIMEOUT_TYPE_MAX) {
                                        log_error("Error parsing 'timeout' config option, ignoring: %s",
                                                  value);
                                        continue;
                                }
                                config->timeout_sec_config = u;
                        }
                        config->timeout_sec = config->timeout_sec_config;

                } else if (streq8(key, "default")) {
                        if (value[0] == '@' && !strcaseeq8(value, "@saved")) {
                                log_error("Unsupported special entry identifier, ignoring: %s", value);
                                continue;
                        }
                        free(config->entry_default_config);
                        config->entry_default_config = xstr8_to_16(value);

                } else if (streq8(key, "editor")) {
                        if (!parse_boolean(value, &config->editor))
                                log_error("Error parsing 'editor' config option, ignoring: %s", value);

                } else if (streq8(key, "auto-entries")) {
                        if (!parse_boolean(value, &config->auto_entries))
                                log_error("Error parsing 'auto-entries' config option, ignoring: %s", value);

                } else if (streq8(key, "auto-firmware")) {
                        if (!parse_boolean(value, &config->auto_firmware))
                                log_error("Error parsing 'auto-firmware' config option, ignoring: %s", value);

                } else if (streq8(key, "auto-poweroff")) {
                        if (!parse_boolean(value, &config->auto_poweroff))
                                log_error("Error parsing 'auto-poweroff' config option, ignoring: %s", value);

                } else if (streq8(key, "auto-reboot")) {
                        if (!parse_boolean(value, &config->auto_reboot))
                                log_error("Error parsing 'auto-reboot' config option, ignoring: %s", value);

                } else if (streq8(key, "beep")) {
                        if (!parse_boolean(value, &config->beep))
                                log_error("Error parsing 'beep' config option, ignoring: %s", value);

                } else if (streq8(key, "reboot-for-bitlocker")) {
                        if (!parse_boolean(value, &config->reboot_for_bitlocker))
                                log_error("Error parsing 'reboot-for-bitlocker' config option, ignoring: %s",
                                          value);

                } else if (streq8(key, "secure-boot-enroll")) {
                        if (streq8(value, "manual"))
                                config->secure_boot_enroll = ENROLL_MANUAL;
                        else if (streq8(value, "force"))
                                config->secure_boot_enroll = ENROLL_FORCE;
                        else if (streq8(value, "if-safe"))
                                config->secure_boot_enroll = ENROLL_IF_SAFE;
                        else if (streq8(value, "off"))
                                config->secure_boot_enroll = ENROLL_OFF;
                        else
                                log_error("Error parsing 'secure-boot-enroll' config option, ignoring: %s",
                                          value);

                } else if (streq8(key, "console-mode")) {
                        if (streq8(value, "auto"))
                                config->console_mode = CONSOLE_MODE_AUTO;
                        else if (streq8(value, "max"))
                                config->console_mode = CONSOLE_MODE_FIRMWARE_MAX;
                        else if (streq8(value, "keep"))
                                config->console_mode = CONSOLE_MODE_KEEP;
                        else {
                                uint64_t u;
                                if (!parse_number8(value, &u, NULL) || u > CONSOLE_MODE_RANGE_MAX) {
                                        log_error("Error parsing 'console-mode' config option, ignoring: %s",
                                                  value);
                                        continue;
                                }
                                config->console_mode = u;
                        }
                }
}

static void boot_entry_parse_tries(
                BootEntry *entry,
                const char16_t *path,
                const char16_t *file,
                const char16_t *suffix) {

        assert(entry);
        assert(path);
        assert(file);
        assert(suffix);

        /*
         * Parses a suffix of two counters (one going down, one going up) in the form "+LEFT-DONE" from the end of the
         * filename (but before the .efi/.conf suffix), where the "-DONE" part is optional and may be left out (in
         * which case that counter as assumed to be zero, i.e. the missing part is synonymous to "-0").
         *
         * Names we grok, and the series they result in:
         *
         * foobar+3.efi   → foobar+2-1.efi → foobar+1-2.efi → foobar+0-3.efi → STOP!
         * foobar+4-0.efi → foobar+3-1.efi → foobar+2-2.efi → foobar+1-3.efi → foobar+0-4.efi → STOP!
         */

        const char16_t *counter = NULL;
        for (;;) {
                char16_t *plus = strchr16(counter ?: file, '+');
                if (plus) {
                        /* We want the last "+". */
                        counter = plus + 1;
                        continue;
                }
                if (counter)
                        break;

                /* No boot counter found. */
                return;
        }

        uint64_t tries_left, tries_done = 0;
        size_t prefix_len = counter - file;

        if (!parse_number16(counter, &tries_left, &counter) || tries_left > INT_MAX)
                return;

        /* Parse done counter only if present. */
        if (*counter == '-' && (!parse_number16(counter + 1, &tries_done, &counter) || tries_done > INT_MAX))
                return;

        /* Boot counter in the middle of the name? */
        if (!streq16(counter, suffix))
                return;

        entry->tries_left = tries_left;
        entry->tries_done = tries_done;
        entry->path = xstrdup16(path);
        entry->current_name = xstrdup16(file);
        entry->next_name = xasprintf(
                        "%.*ls%" PRIu64 "-%" PRIu64 "%ls",
                        (int) prefix_len,
                        file,
                        LESS_BY(tries_left, 1u),
                        MIN(tries_done + 1, (uint64_t) INT_MAX),
                        suffix);
}

static EFI_STATUS boot_entry_bump_counters(BootEntry *entry) {
        _cleanup_free_ char16_t* old_path = NULL, *new_path = NULL;
        _cleanup_(file_closep) EFI_FILE *handle = NULL;
        _cleanup_free_ EFI_FILE_INFO *file_info = NULL;
        size_t file_info_size;
        EFI_STATUS err;

        assert(entry);

        if (entry->tries_left < 0)
                return EFI_SUCCESS;

        if (!entry->path || !entry->current_name || !entry->next_name)
                return EFI_SUCCESS;

        _cleanup_(file_closep) EFI_FILE *root = NULL;
        err = open_volume(entry->device, &root);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Error opening entry root path: %m");

        old_path = xasprintf("%ls\\%ls", entry->path, entry->current_name);

        err = root->Open(root, &handle, old_path, EFI_FILE_MODE_READ|EFI_FILE_MODE_WRITE, 0ULL);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Error opening boot entry: %m");

        err = get_file_info(handle, &file_info, &file_info_size);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Error getting boot entry file info: %m");

        /* And rename the file */
        strcpy16(file_info->FileName, entry->next_name);
        err = handle->SetInfo(handle, MAKE_GUID_PTR(EFI_FILE_INFO), file_info_size, file_info);
        if (err != EFI_SUCCESS)
                return log_error_status(
                                err, "Failed to rename '%ls' to '%ls', ignoring: %m", old_path, entry->next_name);

        /* Flush everything to disk, just in case… */
        err = handle->Flush(handle);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Error flushing boot entry file info: %m");

        /* Let's tell the OS that we renamed this file, so that it knows what to rename to the counter-less name on
         * success */
        new_path = xasprintf("%ls\\%ls", entry->path, entry->next_name);
        efivar_set(MAKE_GUID_PTR(LOADER), u"LoaderBootCountPath", new_path, 0);

        /* If the file we just renamed is the loader path, then let's update that. */
        if (streq16(entry->loader, old_path)) {
                free(entry->loader);
                entry->loader = TAKE_PTR(new_path);
        }

        return EFI_SUCCESS;
}

static void boot_entry_add_type1(
                Config *config,
                EFI_HANDLE *device,
                EFI_FILE *root_dir,
                const char16_t *path,
                const char16_t *file,
                char *content,
                const char16_t *loaded_image_path) {

        _cleanup_(boot_entry_freep) BootEntry *entry = NULL;
        char *line;
        size_t pos = 0, n_initrd = 0;
        char *key, *value;
        EFI_STATUS err;

        assert(config);
        assert(device);
        assert(root_dir);
        assert(path);
        assert(file);
        assert(content);

        entry = xnew(BootEntry, 1);
        *entry = (BootEntry) {
                .tries_done = -1,
                .tries_left = -1,
        };

        while ((line = line_get_key_value(content, " \t", &pos, &key, &value)))
                if (streq8(key, "title")) {
                        free(entry->title);
                        entry->title = xstr8_to_16(value);

                } else if (streq8(key, "sort-key")) {
                        free(entry->sort_key);
                        entry->sort_key = xstr8_to_16(value);

                } else if (streq8(key, "version")) {
                        free(entry->version);
                        entry->version = xstr8_to_16(value);

                } else if (streq8(key, "machine-id")) {
                        free(entry->machine_id);
                        entry->machine_id = xstr8_to_16(value);

                } else if (streq8(key, "linux")) {
                        free(entry->loader);
                        entry->type = LOADER_LINUX;
                        entry->loader = xstr8_to_path(value);
                        entry->key = 'l';

                } else if (streq8(key, "efi")) {
                        entry->type = LOADER_EFI;
                        free(entry->loader);
                        entry->loader = xstr8_to_path(value);

                        /* do not add an entry for ourselves */
                        if (strcaseeq16(entry->loader, loaded_image_path)) {
                                entry->type = LOADER_UNDEFINED;
                                break;
                        }

                } else if (streq8(key, "architecture")) {
                        /* do not add an entry for an EFI image of architecture not matching with that of the image */
                        if (!streq8(value, EFI_MACHINE_TYPE_NAME)) {
                                entry->type = LOADER_UNDEFINED;
                                break;
                        }

                } else if (streq8(key, "devicetree")) {
                        free(entry->devicetree);
                        entry->devicetree = xstr8_to_path(value);

                } else if (streq8(key, "initrd")) {
                        entry->initrd = xrealloc(
                                entry->initrd,
                                n_initrd == 0 ? 0 : (n_initrd + 1) * sizeof(uint16_t *),
                                (n_initrd + 2) * sizeof(uint16_t *));
                        entry->initrd[n_initrd++] = xstr8_to_path(value);
                        entry->initrd[n_initrd] = NULL;

                } else if (streq8(key, "options")) {
                        _cleanup_free_ char16_t *new = NULL;

                        new = xstr8_to_16(value);
                        if (entry->options) {
                                char16_t *s = xasprintf("%ls %ls", entry->options, new);
                                free(entry->options);
                                entry->options = s;
                        } else
                                entry->options = TAKE_PTR(new);
                }

        if (entry->type == LOADER_UNDEFINED)
                return;

        /* check existence */
        _cleanup_(file_closep) EFI_FILE *handle = NULL;
        err = root_dir->Open(root_dir, &handle, entry->loader, EFI_FILE_MODE_READ, 0ULL);
        if (err != EFI_SUCCESS)
                return;

        entry->device = device;
        entry->id = xstrdup16(file);
        strtolower16(entry->id);

        config_add_entry(config, entry);

        boot_entry_parse_tries(entry, path, file, u".conf");
        TAKE_PTR(entry);
}

static EFI_STATUS efivar_get_timeout(const char16_t *var, uint64_t *ret_value) {
        _cleanup_free_ char16_t *value = NULL;
        EFI_STATUS err;

        assert(var);
        assert(ret_value);

        err = efivar_get(MAKE_GUID_PTR(LOADER), var, &value);
        if (err != EFI_SUCCESS)
                return err;

        if (streq16(value, u"menu-disabled")) {
                *ret_value = TIMEOUT_MENU_DISABLED;
                return EFI_SUCCESS;
        }
        if (streq16(value, u"menu-force")) {
                *ret_value = TIMEOUT_MENU_FORCE;
                return EFI_SUCCESS;
        }
        if (streq16(value, u"menu-hidden")) {
                *ret_value = TIMEOUT_MENU_HIDDEN;
                return EFI_SUCCESS;
        }

        uint64_t timeout;
        if (!parse_number16(value, &timeout, NULL))
                return EFI_INVALID_PARAMETER;

        *ret_value = MIN(timeout, TIMEOUT_TYPE_MAX);
        return EFI_SUCCESS;
}

static void config_load_defaults(Config *config, EFI_FILE *root_dir) {
        _cleanup_free_ char *content = NULL;
        size_t content_size, value = 0;  /* avoid false maybe-uninitialized warning */
        EFI_STATUS err;

        assert(root_dir);

        *config = (Config) {
                .editor = true,
                .auto_entries = true,
                .auto_firmware = true,
                .secure_boot_enroll = ENROLL_IF_SAFE,
                .idx_default_efivar = IDX_INVALID,
                .console_mode = CONSOLE_MODE_KEEP,
                .console_mode_efivar = CONSOLE_MODE_KEEP,
                .timeout_sec_config = TIMEOUT_UNSET,
                .timeout_sec_efivar = TIMEOUT_UNSET,
        };

        err = file_read(root_dir, u"\\loader\\loader.conf", 0, 0, &content, &content_size);
        if (err == EFI_SUCCESS) {
                /* First, measure. */
                err = tpm_log_tagged_event(
                                TPM2_PCR_BOOT_LOADER_CONFIG,
                                POINTER_TO_PHYSICAL_ADDRESS(content),
                                content_size,
                                LOADER_CONF_EVENT_TAG_ID,
                                u"loader.conf",
                                /* ret_measured= */ NULL);
                if (err != EFI_SUCCESS)
                        log_error_status(err, "Error measuring loader.conf into TPM: %m");

                /* Then: parse */
                config_defaults_load_from_file(config, content);
        }

        err = efivar_get_timeout(u"LoaderConfigTimeout", &config->timeout_sec_efivar);
        if (err == EFI_SUCCESS)
                config->timeout_sec = config->timeout_sec_efivar;
        else if (err != EFI_NOT_FOUND)
                log_error_status(err, "Error reading LoaderConfigTimeout EFI variable: %m");

        err = efivar_get_timeout(u"LoaderConfigTimeoutOneShot", &config->timeout_sec);
        if (err == EFI_SUCCESS) {
                /* Unset variable now, after all it's "one shot". */
                (void) efivar_unset(MAKE_GUID_PTR(LOADER), u"LoaderConfigTimeoutOneShot", EFI_VARIABLE_NON_VOLATILE);

                config->force_menu = true; /* force the menu when this is set */
        } else if (err != EFI_NOT_FOUND)
                log_error_status(err, "Error reading LoaderConfigTimeoutOneShot EFI variable: %m");

        err = efivar_get_uint_string(MAKE_GUID_PTR(LOADER), u"LoaderConfigConsoleMode", &value);
        if (err == EFI_SUCCESS)
                config->console_mode_efivar = value;

        err = efivar_get(MAKE_GUID_PTR(LOADER), u"LoaderEntryOneShot", &config->entry_oneshot);
        if (err == EFI_SUCCESS)
                /* Unset variable now, after all it's "one shot". */
                (void) efivar_unset(MAKE_GUID_PTR(LOADER), u"LoaderEntryOneShot", EFI_VARIABLE_NON_VOLATILE);

        (void) efivar_get(MAKE_GUID_PTR(LOADER), u"LoaderEntryDefault", &config->entry_default_efivar);

        strtolower16(config->entry_default_config);
        strtolower16(config->entry_default_efivar);
        strtolower16(config->entry_oneshot);
        strtolower16(config->entry_saved);

        config->use_saved_entry = streq16(config->entry_default_config, u"@saved");
        config->use_saved_entry_efivar = streq16(config->entry_default_efivar, u"@saved");
        if (config->use_saved_entry || config->use_saved_entry_efivar)
                (void) efivar_get(MAKE_GUID_PTR(LOADER), u"LoaderEntryLastBooted", &config->entry_saved);
}

static void config_load_type1_entries(
                Config *config,
                EFI_HANDLE *device,
                EFI_FILE *root_dir,
                const char16_t *loaded_image_path) {

        _cleanup_(file_closep) EFI_FILE *entries_dir = NULL;
        _cleanup_free_ EFI_FILE_INFO *f = NULL;
        size_t f_size = 0;
        EFI_STATUS err;

        assert(config);
        assert(device);
        assert(root_dir);

        /* Adds Boot Loader Type #1 entries (i.e. /loader/entries/….conf) */

        err = open_directory(root_dir, u"\\loader\\entries", &entries_dir);
        if (err != EFI_SUCCESS)
                return;

        for (;;) {
                _cleanup_free_ char *content = NULL;

                err = readdir(entries_dir, &f, &f_size);
                if (err != EFI_SUCCESS || !f)
                        break;

                if (f->FileName[0] == '.')
                        continue;
                if (FLAGS_SET(f->Attribute, EFI_FILE_DIRECTORY))
                        continue;

                if (!endswith_no_case(f->FileName, u".conf"))
                        continue;
                if (startswith(f->FileName, u"auto-"))
                        continue;

                err = file_read(entries_dir, f->FileName, 0, 0, &content, NULL);
                if (err == EFI_SUCCESS)
                        boot_entry_add_type1(config, device, root_dir, u"\\loader\\entries", f->FileName, content, loaded_image_path);
        }
}

static int boot_entry_compare_indirect(const BootEntry **a_ind, const BootEntry **b_ind) {
        const BootEntry *a = *ASSERT_PTR(a_ind), *b = *ASSERT_PTR(b_ind);
        int r;

        /* Order entries that have no tries left to the end of the list */
        r = CMP(a->tries_left == 0, b->tries_left == 0);
        if (r != 0)
                return r;

        /* If there's a sort key defined for *both* entries, then we do new-style ordering, i.e. by
         * sort-key/machine-id/version, with a final fallback to id. If there's no sort key for either, we do
         * old-style ordering, i.e. by id only. If one has sort key and the other does not, we put new-style
         * before old-style. */
        r = CMP(!a->sort_key, !b->sort_key);
        if (r != 0) /* one is old-style, one new-style */
                return r;

        if (a->sort_key && b->sort_key) {
                r = strcmp16(a->sort_key, b->sort_key);
                if (r != 0)
                        return r;

                /* If multiple installations of the same OS are around, group by machine ID */
                r = strcmp16(a->machine_id, b->machine_id);
                if (r != 0)
                        return r;

                /* If the sort key was defined, then order by version now (downwards, putting the newest first) */
                r = -strverscmp_improved(a->version, b->version);
                if (r != 0)
                        return r;
        }

        /* Now order by ID. The version is likely part of the ID, thus note that this will generatelly put
         * the newer versions earlier. Specifying a sort key explicitly is preferable, because it gives an
         * explicit sort order. */
        r = -strverscmp_improved(a->id, b->id);
        if (r != 0)
                return r;

        if (a->tries_left < 0 || b->tries_left < 0)
                return 0;

        /* If both items have boot counting, and otherwise are identical, put the entry with more tries left first */
        r = -CMP(a->tries_left, b->tries_left);
        if (r != 0)
                return r;

        /* If they have the same number of tries left, then let the one win which was tried fewer times so far */
        return CMP(a->tries_done, b->tries_done);
}

static size_t config_find_entry(Config *config, const char16_t *pattern) {
        assert(config);

        /* We expect pattern and entry IDs to be already case folded. */

        if (!pattern)
                return IDX_INVALID;

        for (size_t i = 0; i < config->n_entries; i++)
                if (efi_fnmatch(pattern, config->entries[i]->id))
                        return i;

        return IDX_INVALID;
}

static void config_select_default_entry(Config *config) {
        size_t i;

        assert(config);

        i = config_find_entry(config, config->entry_oneshot);
        if (i != IDX_INVALID) {
                config->idx_default = i;
                return;
        }

        i = config_find_entry(config, config->use_saved_entry_efivar ? config->entry_saved : config->entry_default_efivar);
        if (i != IDX_INVALID) {
                config->idx_default = i;
                config->idx_default_efivar = i;
                return;
        }

        if (config->use_saved_entry)
                /* No need to do the same thing twice. */
                i = config->use_saved_entry_efivar ? IDX_INVALID : config_find_entry(config, config->entry_saved);
        else
                i = config_find_entry(config, config->entry_default_config);
        if (i != IDX_INVALID) {
                config->idx_default = i;
                return;
        }

        /* select the first suitable entry */
        for (i = 0; i < config->n_entries; i++)
                if (config->entries[i]->type != LOADER_AUTO && !config->entries[i]->call) {
                        config->idx_default = i;
                        return;
                }

        /* If no configured entry to select from was found, enable the menu. */
        config->idx_default = 0;
        if (config->timeout_sec == 0)
                config->timeout_sec = 10;
}

static bool entries_unique(BootEntry **entries, bool *unique, size_t n_entries) {
        bool is_unique = true;

        assert(entries);
        assert(unique);

        for (size_t i = 0; i < n_entries; i++)
                for (size_t k = i + 1; k < n_entries; k++) {
                        if (!streq16(entries[i]->title_show, entries[k]->title_show))
                                continue;

                        is_unique = unique[i] = unique[k] = false;
                }

        return is_unique;
}

/* generate unique titles, avoiding non-distinguishable menu entries */
static void generate_boot_entry_titles(Config *config) {
        assert(config);

        bool unique[config->n_entries];

        /* set title */
        for (size_t i = 0; i < config->n_entries; i++) {
                assert(!config->entries[i]->title_show);
                unique[i] = true;
                config->entries[i]->title_show = xstrdup16(config->entries[i]->title ?: config->entries[i]->id);
        }

        if (entries_unique(config->entries, unique, config->n_entries))
                return;

        /* add version to non-unique titles */
        for (size_t i = 0; i < config->n_entries; i++) {
                if (unique[i])
                        continue;

                unique[i] = true;

                if (!config->entries[i]->version)
                        continue;

                _cleanup_free_ char16_t *t = config->entries[i]->title_show;
                config->entries[i]->title_show = xasprintf("%ls (%ls)", t, config->entries[i]->version);
        }

        if (entries_unique(config->entries, unique, config->n_entries))
                return;

        /* add machine-id to non-unique titles */
        for (size_t i = 0; i < config->n_entries; i++) {
                if (unique[i])
                        continue;

                unique[i] = true;

                if (!config->entries[i]->machine_id)
                        continue;

                _cleanup_free_ char16_t *t = config->entries[i]->title_show;
                config->entries[i]->title_show = xasprintf("%ls (%.8ls)", t, config->entries[i]->machine_id);
        }

        if (entries_unique(config->entries, unique, config->n_entries))
                return;

        /* add file name to non-unique titles */
        for (size_t i = 0; i < config->n_entries; i++) {
                if (unique[i])
                        continue;

                _cleanup_free_ char16_t *t = config->entries[i]->title_show;
                config->entries[i]->title_show = xasprintf("%ls (%ls)", t, config->entries[i]->id);
        }
}

static bool is_sd_boot(EFI_FILE *root_dir, const char16_t *loader_path) {
        EFI_STATUS err;
        size_t read, n_sections;
        _cleanup_free_ PeSectionDescriptor *sections = NULL;
        _cleanup_free_ char *content = NULL;

        assert(root_dir);
        assert(loader_path);

        err = pe_file_locate_sections(root_dir, loader_path, &sections, &n_sections);
        if (err != EFI_SUCCESS)
                return false;

        PeSectionDescriptor *sdmagic_section = pe_find_section(sections, n_sections, ".sdmagic");
        if (!sdmagic_section)
                return false;

        err = file_read(root_dir, loader_path, sdmagic_section->offset, sdmagic_section->size, &content, &read);
        if (err != EFI_SUCCESS || sdmagic_section->size != read)
                return false;

        return memcmp(content, SD_MAGIC, sizeof(SD_MAGIC)) == 0;
}

static BootEntry* config_add_entry_loader_auto(
                Config *config,
                EFI_HANDLE *device,
                EFI_FILE *root_dir,
                const char16_t *loaded_image_path,
                const char16_t *id,
                char16_t key,
                const char16_t *title,
                const char16_t *loader) {

        assert(config);
        assert(device);
        assert(root_dir);
        assert(id);
        assert(title);

        if (!config->auto_entries)
                return NULL;

        if (!loader) {
                loader = u"\\EFI\\BOOT\\BOOT" EFI_MACHINE_TYPE_NAME ".efi";

                /* We are trying to add the default EFI loader here,
                 * but we do not want to do that if that would be us.
                 *
                 * If the default loader is not us, it might be shim. It would
                 * chainload GRUBX64.EFI in that case, which might be us. */
                if (strcaseeq16(loader, loaded_image_path) ||
                    is_sd_boot(root_dir, loader) ||
                    is_sd_boot(root_dir, u"\\EFI\\BOOT\\GRUB" EFI_MACHINE_TYPE_NAME u".EFI"))
                        return NULL;
        }

        /* check existence */
        _cleanup_(file_closep) EFI_FILE *handle = NULL;
        EFI_STATUS err = root_dir->Open(root_dir, &handle, (char16_t *) loader, EFI_FILE_MODE_READ, 0ULL);
        if (err != EFI_SUCCESS)
                return NULL;

        BootEntry *entry = xnew(BootEntry, 1);
        *entry = (BootEntry) {
                .id = xstrdup16(id),
                .type = LOADER_AUTO,
                .title = xstrdup16(title),
                .device = device,
                .loader = xstrdup16(loader),
                .key = key,
                .tries_done = -1,
                .tries_left = -1,
        };

        config_add_entry(config, entry);
        return entry;
}

static void config_add_entry_osx(Config *config) {
        EFI_STATUS err;
        size_t n_handles = 0;
        _cleanup_free_ EFI_HANDLE *handles = NULL;

        assert(config);

        if (!config->auto_entries)
                return;

        err = BS->LocateHandleBuffer(
                        ByProtocol, MAKE_GUID_PTR(EFI_SIMPLE_FILE_SYSTEM_PROTOCOL), NULL, &n_handles, &handles);
        if (err != EFI_SUCCESS)
                return;

        for (size_t i = 0; i < n_handles; i++) {
                _cleanup_(file_closep) EFI_FILE *root = NULL;

                if (open_volume(handles[i], &root) != EFI_SUCCESS)
                        continue;

                if (config_add_entry_loader_auto(
                                config,
                                handles[i],
                                root,
                                NULL,
                                u"auto-osx",
                                'a',
                                u"macOS",
                                u"\\System\\Library\\CoreServices\\boot.efi"))
                        break;
        }
}

#if defined(__i386__) || defined(__x86_64__) || defined(__arm__) || defined(__aarch64__)
static EFI_STATUS boot_windows_bitlocker(void) {
        _cleanup_free_ EFI_HANDLE *handles = NULL;
        size_t n_handles;
        EFI_STATUS err;

        // FIXME: Experimental for now. Should be generalized, and become a per-entry option that can be
        // enabled independently of BitLocker, and without a BootXXXX entry pre-existing.

        /* BitLocker key cannot be sealed without a TPM present. */
        if (!tpm_present())
                return EFI_NOT_FOUND;

        err = BS->LocateHandleBuffer(
                        ByProtocol, MAKE_GUID_PTR(EFI_BLOCK_IO_PROTOCOL), NULL, &n_handles, &handles);
        if (err != EFI_SUCCESS)
                return err;

        /* Look for BitLocker magic string on all block drives. */
        bool found = false;
        for (size_t i = 0; i < n_handles; i++) {
                EFI_BLOCK_IO_PROTOCOL *block_io;
                err = BS->HandleProtocol(handles[i], MAKE_GUID_PTR(EFI_BLOCK_IO_PROTOCOL), (void **) &block_io);
                if (err != EFI_SUCCESS || block_io->Media->BlockSize < 512 || block_io->Media->BlockSize > 4096)
                        continue;

                char buf[4096];
                err = block_io->ReadBlocks(block_io, block_io->Media->MediaId, 0, sizeof(buf), buf);
                if (err != EFI_SUCCESS)
                        continue;

                if (memcmp(buf + 3, "-FVE-FS-", STRLEN("-FVE-FS-")) == 0) {
                        found = true;
                        break;
                }
        }

        /* If no BitLocker drive was found, we can just chainload bootmgfw.efi directly. */
        if (!found)
                return EFI_NOT_FOUND;

        _cleanup_free_ uint16_t *boot_order = NULL;
        size_t boot_order_size;

        /* There can be gaps in Boot#### entries. Instead of iterating over the full
         * EFI var list or uint16_t namespace, just look for "Windows Boot Manager" in BootOrder. */
        err = efivar_get_raw(MAKE_GUID_PTR(EFI_GLOBAL_VARIABLE), u"BootOrder", (char **) &boot_order, &boot_order_size);
        if (err != EFI_SUCCESS || boot_order_size % sizeof(uint16_t) != 0)
                return err;

        for (size_t i = 0; i < boot_order_size / sizeof(uint16_t); i++) {
                _cleanup_free_ char *buf = NULL;
                size_t buf_size;

                _cleanup_free_ char16_t *name = xasprintf("Boot%04x", boot_order[i]);
                err = efivar_get_raw(MAKE_GUID_PTR(EFI_GLOBAL_VARIABLE), name, &buf, &buf_size);
                if (err != EFI_SUCCESS)
                        continue;

                /* Boot#### are EFI_LOAD_OPTION. But we really are only interested
                 * for the description, which is at this offset. */
                size_t offset = sizeof(uint32_t) + sizeof(uint16_t);
                if (buf_size < offset + sizeof(char16_t))
                        continue;

                if (streq16((char16_t *) (buf + offset), u"Windows Boot Manager")) {
                        err = efivar_set_raw(
                                MAKE_GUID_PTR(EFI_GLOBAL_VARIABLE),
                                u"BootNext",
                                boot_order + i,
                                sizeof(boot_order[i]),
                                EFI_VARIABLE_NON_VOLATILE);
                        if (err != EFI_SUCCESS)
                                return err;
                        RT->ResetSystem(EfiResetWarm, EFI_SUCCESS, 0, NULL);
                        assert_not_reached();
                }
        }

        return EFI_NOT_FOUND;
}
#endif

static void config_add_entry_windows(Config *config, EFI_HANDLE *device, EFI_FILE *root_dir) {
#if defined(__i386__) || defined(__x86_64__) || defined(__arm__) || defined(__aarch64__)
        _cleanup_free_ char *bcd = NULL;
        char16_t *title = NULL;
        EFI_STATUS err;
        size_t len;

        assert(config);
        assert(device);
        assert(root_dir);

        if (!config->auto_entries)
                return;

        /* Try to find a better title. */
        err = file_read(root_dir, u"\\EFI\\Microsoft\\Boot\\BCD", 0, 100*1024, &bcd, &len);
        if (err == EFI_SUCCESS)
                title = get_bcd_title((uint8_t *) bcd, len);

        BootEntry *e = config_add_entry_loader_auto(config, device, root_dir, NULL,
                                                    u"auto-windows", 'w', title ?: u"Windows Boot Manager",
                                                    u"\\EFI\\Microsoft\\Boot\\bootmgfw.efi");

        if (config->reboot_for_bitlocker)
                e->call = boot_windows_bitlocker;
#endif
}

static void config_load_type2_entries(
                Config *config,
                EFI_HANDLE *device,
                EFI_FILE *root_dir) {

        _cleanup_(file_closep) EFI_FILE *linux_dir = NULL;
        _cleanup_free_ EFI_FILE_INFO *f = NULL;
        size_t f_size = 0;
        EFI_STATUS err;

        /* Adds Boot Loader Type #2 entries (i.e. /EFI/Linux/….efi) */

        assert(config);
        assert(device);
        assert(root_dir);

        err = open_directory(root_dir, u"\\EFI\\Linux", &linux_dir);
        if (err != EFI_SUCCESS)
                return;

        for (;;) {
                _cleanup_free_ char16_t *os_pretty_name = NULL, *os_image_id = NULL, *os_name = NULL, *os_id = NULL,
                        *os_image_version = NULL, *os_version = NULL, *os_version_id = NULL, *os_build_id = NULL;
                const char16_t *good_name, *good_version, *good_sort_key;
                _cleanup_free_ char *content = NULL;
                _cleanup_free_ PeSectionDescriptor *sections = NULL;
                size_t n_sections;
                size_t pos = 0;
                char *line, *key, *value;

                err = readdir(linux_dir, &f, &f_size);
                if (err != EFI_SUCCESS || !f)
                        break;

                if (f->FileName[0] == '.')
                        continue;
                if (FLAGS_SET(f->Attribute, EFI_FILE_DIRECTORY))
                        continue;
                if (!endswith_no_case(f->FileName, u".efi"))
                        continue;
                if (startswith(f->FileName, u"auto-"))
                        continue;

                /* look for .osrel and .cmdline sections in the .efi binary */
                err = pe_file_locate_sections(linux_dir, f->FileName, &sections, &n_sections);
                if (err != EFI_SUCCESS)
                        continue;

                PeSectionDescriptor *section_osrel = pe_find_section(sections, n_sections, ".osrel");
                if (!section_osrel)
                        continue;
                err = file_read(linux_dir, f->FileName, section_osrel->offset, section_osrel->size, &content, NULL);
                if (err != EFI_SUCCESS)
                        continue;

                /* read properties from the embedded os-release file */
                while ((line = line_get_key_value(content, "=", &pos, &key, &value)))
                        if (streq8(key, "PRETTY_NAME")) {
                                free(os_pretty_name);
                                os_pretty_name = xstr8_to_16(value);

                        } else if (streq8(key, "IMAGE_ID")) {
                                free(os_image_id);
                                os_image_id = xstr8_to_16(value);

                        } else if (streq8(key, "NAME")) {
                                free(os_name);
                                os_name = xstr8_to_16(value);

                        } else if (streq8(key, "ID")) {
                                free(os_id);
                                os_id = xstr8_to_16(value);

                        } else if (streq8(key, "IMAGE_VERSION")) {
                                free(os_image_version);
                                os_image_version = xstr8_to_16(value);

                        } else if (streq8(key, "VERSION")) {
                                free(os_version);
                                os_version = xstr8_to_16(value);

                        } else if (streq8(key, "VERSION_ID")) {
                                free(os_version_id);
                                os_version_id = xstr8_to_16(value);

                        } else if (streq8(key, "BUILD_ID")) {
                                free(os_build_id);
                                os_build_id = xstr8_to_16(value);
                        }

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
                        continue;

                BootEntry *entry = xnew(BootEntry, 1);
                *entry = (BootEntry) {
                        .id = xstrdup16(f->FileName),
                        .type = LOADER_UNIFIED_LINUX,
                        .title = xstrdup16(good_name),
                        .version = xstrdup16(good_version),
                        .device = device,
                        .loader = xasprintf("\\EFI\\Linux\\%ls", f->FileName),
                        .sort_key = xstrdup16(good_sort_key),
                        .key = 'l',
                        .tries_done = -1,
                        .tries_left = -1,
                };

                strtolower16(entry->id);
                config_add_entry(config, entry);
                boot_entry_parse_tries(entry, u"\\EFI\\Linux", f->FileName, u".efi");

                PeSectionDescriptor *section_cmdline = pe_find_section(sections, n_sections, ".cmdline");
                if (!section_cmdline)
                        continue;

                content = mfree(content);

                /* read the embedded cmdline file */
                size_t cmdline_len;
                err = file_read(linux_dir, f->FileName, section_cmdline->offset, section_cmdline->size, &content, &cmdline_len);
                if (err == EFI_SUCCESS) {
                        entry->options = xstrn8_to_16(content, cmdline_len);
                        mangle_stub_cmdline(entry->options);
                        entry->options_implied = true;
                }
        }
}

static void config_load_xbootldr(
                Config *config,
                EFI_HANDLE *device) {

        _cleanup_(file_closep) EFI_FILE *root_dir = NULL;
        EFI_HANDLE new_device = NULL;  /* avoid false maybe-uninitialized warning */
        EFI_STATUS err;

        assert(config);
        assert(device);

        err = partition_open(MAKE_GUID_PTR(XBOOTLDR), device, &new_device, &root_dir);
        if (err != EFI_SUCCESS)
                return;

        config_load_type2_entries(config, new_device, root_dir);
        config_load_type1_entries(config, new_device, root_dir, NULL);
}

static EFI_STATUS initrd_prepare(
                EFI_FILE *root,
                const BootEntry *entry,
                char16_t **ret_options,
                void **ret_initrd,
                size_t *ret_initrd_size) {

        assert(root);
        assert(entry);
        assert(ret_options);
        assert(ret_initrd);
        assert(ret_initrd_size);

        if (entry->type != LOADER_LINUX || !entry->initrd) {
                ret_options = NULL;
                ret_initrd = NULL;
                ret_initrd_size = 0;
                return EFI_SUCCESS;
        }

        /* Note that order of initrds matters. The kernel will only look for microcode updates in the very
         * first one it sees. */

        /* Add initrd= to options for older kernels that do not support LINUX_INITRD_MEDIA. Should be dropped
         * if linux_x86.c is dropped. */
        _cleanup_free_ char16_t *options = NULL;

        EFI_STATUS err;
        size_t size = 0;
        _cleanup_free_ uint8_t *initrd = NULL;

        STRV_FOREACH(i, entry->initrd) {
                _cleanup_free_ char16_t *o = options;
                if (o)
                        options = xasprintf("%ls initrd=%ls", o, *i);
                else
                        options = xasprintf("initrd=%ls", *i);

                _cleanup_(file_closep) EFI_FILE *handle = NULL;
                err = root->Open(root, &handle, *i, EFI_FILE_MODE_READ, 0);
                if (err != EFI_SUCCESS)
                        return err;

                _cleanup_free_ EFI_FILE_INFO *info = NULL;
                err = get_file_info(handle, &info, NULL);
                if (err != EFI_SUCCESS)
                        return err;

                if (info->FileSize == 0) /* Automatically skip over empty files */
                        continue;

                size_t new_size, read_size = info->FileSize;
                if (__builtin_add_overflow(size, read_size, &new_size))
                        return EFI_OUT_OF_RESOURCES;
                initrd = xrealloc(initrd, size, new_size);

                err = chunked_read(handle, &read_size, initrd + size);
                if (err != EFI_SUCCESS)
                        return err;

                /* Make sure the actual read size is what we expected. */
                assert(size + read_size == new_size);
                size = new_size;
        }

        if (entry->options) {
                _cleanup_free_ char16_t *o = options;
                options = xasprintf("%ls %ls", o, entry->options);
        }

        *ret_options = TAKE_PTR(options);
        *ret_initrd = TAKE_PTR(initrd);
        *ret_initrd_size = size;
        return EFI_SUCCESS;
}

static EFI_STATUS image_start(
                EFI_HANDLE parent_image,
                const BootEntry *entry) {

        _cleanup_(devicetree_cleanup) struct devicetree_state dtstate = {};
        _cleanup_(unload_imagep) EFI_HANDLE image = NULL;
        _cleanup_free_ EFI_DEVICE_PATH *path = NULL;
        EFI_STATUS err;

        assert(entry);

        /* If this loader entry has a special way to boot, try that first. */
        if (entry->call)
                (void) entry->call();

        _cleanup_(file_closep) EFI_FILE *image_root = NULL;
        err = open_volume(entry->device, &image_root);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Error opening root path: %m");

        err = make_file_device_path(entry->device, entry->loader, &path);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Error making file device path: %m");

        size_t initrd_size = 0;
        _cleanup_free_ void *initrd = NULL;
        _cleanup_free_ char16_t *options_initrd = NULL;
        err = initrd_prepare(image_root, entry, &options_initrd, &initrd, &initrd_size);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Error preparing initrd: %m");

        err = shim_load_image(parent_image, path, &image);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Error loading %ls: %m", entry->loader);

        /* DTBs are loaded by the kernel before ExitBootServices, and they can be used to map and assign
         * arbitrary memory ranges, so skip them when secure boot is enabled as the DTB here is unverified.
         */
        if (entry->devicetree && !secure_boot_enabled()) {
                err = devicetree_install(&dtstate, image_root, entry->devicetree);
                if (err != EFI_SUCCESS)
                        return log_error_status(err, "Error loading %ls: %m", entry->devicetree);
        }

        _cleanup_(cleanup_initrd) EFI_HANDLE initrd_handle = NULL;
        err = initrd_register(initrd, initrd_size, &initrd_handle);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Error registering initrd: %m");

        EFI_LOADED_IMAGE_PROTOCOL *loaded_image;
        err = BS->HandleProtocol(image, MAKE_GUID_PTR(EFI_LOADED_IMAGE_PROTOCOL), (void **) &loaded_image);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Error getting LoadedImageProtocol handle: %m");

        /* If we had to append an initrd= entry to the command line, we have to pass it, and measure it.
         * Otherwise, only pass/measure it if it is not implicit anyway (i.e. embedded into the UKI or
         * so). */
        char16_t *options = options_initrd ?: entry->options_implied ? NULL : entry->options;
        if (options) {
                loaded_image->LoadOptions = options;
                loaded_image->LoadOptionsSize = strsize16(options);

                /* Try to log any options to the TPM, especially to catch manually edited options */
                (void) tpm_log_load_options(options, NULL);
        }

        efivar_set_time_usec(MAKE_GUID_PTR(LOADER), u"LoaderTimeExecUSec", 0);
        err = BS->StartImage(image, NULL, NULL);
        graphics_mode(false);
        if (err == EFI_SUCCESS)
                return EFI_SUCCESS;

        /* Try calling the kernel compat entry point if one exists. */
        if (err == EFI_UNSUPPORTED && entry->type == LOADER_LINUX) {
                uint32_t compat_address;

                err = pe_kernel_info(loaded_image->ImageBase, &compat_address);
                if (err != EFI_SUCCESS) {
                        if (err != EFI_UNSUPPORTED)
                                return log_error_status(err, "Error finding kernel compat entry address: %m");
                } else if (compat_address > 0) {
                        EFI_IMAGE_ENTRY_POINT kernel_entry =
                                (EFI_IMAGE_ENTRY_POINT) ((uint8_t *) loaded_image->ImageBase + compat_address);

                        err = kernel_entry(image, ST);
                        graphics_mode(false);
                        if (err == EFI_SUCCESS)
                                return EFI_SUCCESS;
                } else
                        err = EFI_UNSUPPORTED;
        }

        return log_error_status(err, "Failed to execute %ls (%ls): %m", entry->title_show, entry->loader);
}

static void config_free(Config *config) {
        assert(config);
        for (size_t i = 0; i < config->n_entries; i++)
                boot_entry_free(config->entries[i]);
        free(config->entries);
        free(config->entry_default_config);
        free(config->entry_default_efivar);
        free(config->entry_oneshot);
        free(config->entry_saved);
}

static void config_write_entries_to_variable(Config *config) {
        _cleanup_free_ char *buffer = NULL;
        size_t sz = 0;
        char *p;

        assert(config);

        for (size_t i = 0; i < config->n_entries; i++)
                sz += strsize16(config->entries[i]->id);

        p = buffer = xmalloc(sz);

        for (size_t i = 0; i < config->n_entries; i++)
                p = mempcpy(p, config->entries[i]->id, strsize16(config->entries[i]->id));

        assert(p == buffer + sz);

        /* Store the full list of discovered entries. */
        (void) efivar_set_raw(MAKE_GUID_PTR(LOADER), u"LoaderEntries", buffer, sz, 0);
}

static void save_selected_entry(const Config *config, const BootEntry *entry) {
        assert(config);
        assert(entry);
        assert(entry->loader || !entry->call);

        /* Always export the selected boot entry to the system in a volatile var. */
        (void) efivar_set(MAKE_GUID_PTR(LOADER), u"LoaderEntrySelected", entry->id, 0);

        /* Do not save or delete if this was a oneshot boot. */
        if (streq16(config->entry_oneshot, entry->id))
                return;

        if (config->use_saved_entry_efivar || (!config->entry_default_efivar && config->use_saved_entry)) {
                /* Avoid unnecessary NVRAM writes. */
                if (streq16(config->entry_saved, entry->id))
                        return;

                (void) efivar_set(MAKE_GUID_PTR(LOADER), u"LoaderEntryLastBooted", entry->id, EFI_VARIABLE_NON_VOLATILE);
        } else
                /* Delete the non-volatile var if not needed. */
                (void) efivar_unset(MAKE_GUID_PTR(LOADER), u"LoaderEntryLastBooted", EFI_VARIABLE_NON_VOLATILE);
}

static EFI_STATUS secure_boot_discover_keys(Config *config, EFI_FILE *root_dir) {
        EFI_STATUS err;
        _cleanup_(file_closep) EFI_FILE *keys_basedir = NULL;

        if (secure_boot_mode() != SECURE_BOOT_SETUP)
                return EFI_SUCCESS;

        /* the lack of a 'keys' directory is not fatal and is silently ignored */
        err = open_directory(root_dir, u"\\loader\\keys", &keys_basedir);
        if (err == EFI_NOT_FOUND)
                return EFI_SUCCESS;
        if (err != EFI_SUCCESS)
                return err;

        for (;;) {
                _cleanup_free_ EFI_FILE_INFO *dirent = NULL;
                size_t dirent_size = 0;
                BootEntry *entry = NULL;

                err = readdir(keys_basedir, &dirent, &dirent_size);
                if (err != EFI_SUCCESS || !dirent)
                        return err;

                if (dirent->FileName[0] == '.')
                        continue;

                if (!FLAGS_SET(dirent->Attribute, EFI_FILE_DIRECTORY))
                        continue;

                entry = xnew(BootEntry, 1);
                *entry = (BootEntry) {
                        .id = xasprintf("secure-boot-keys-%ls", dirent->FileName),
                        .title = xasprintf("Enroll Secure Boot keys: %ls", dirent->FileName),
                        .path = xasprintf("\\loader\\keys\\%ls", dirent->FileName),
                        .type = LOADER_SECURE_BOOT_KEYS,
                        .tries_done = -1,
                        .tries_left = -1,
                };
                config_add_entry(config, entry);

                if (IN_SET(config->secure_boot_enroll, ENROLL_IF_SAFE, ENROLL_FORCE) &&
                    strcaseeq16(dirent->FileName, u"auto"))
                        /* If we auto enroll successfully this call does not return.
                         * If it fails we still want to add other potential entries to the menu. */
                        secure_boot_enroll_at(root_dir, entry->path, config->secure_boot_enroll == ENROLL_FORCE);
        }

        return EFI_SUCCESS;
}

static void export_variables(
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                const char16_t *loaded_image_path,
                uint64_t init_usec) {

        static const uint64_t loader_features =
                EFI_LOADER_FEATURE_CONFIG_TIMEOUT |
                EFI_LOADER_FEATURE_CONFIG_TIMEOUT_ONE_SHOT |
                EFI_LOADER_FEATURE_ENTRY_DEFAULT |
                EFI_LOADER_FEATURE_ENTRY_ONESHOT |
                EFI_LOADER_FEATURE_BOOT_COUNTING |
                EFI_LOADER_FEATURE_XBOOTLDR |
                EFI_LOADER_FEATURE_RANDOM_SEED |
                EFI_LOADER_FEATURE_LOAD_DRIVER |
                EFI_LOADER_FEATURE_SORT_KEY |
                EFI_LOADER_FEATURE_SAVED_ENTRY |
                EFI_LOADER_FEATURE_DEVICETREE |
                EFI_LOADER_FEATURE_SECUREBOOT_ENROLL |
                EFI_LOADER_FEATURE_RETAIN_SHIM |
                EFI_LOADER_FEATURE_MENU_DISABLE |
                0;

        _cleanup_free_ char16_t *infostr = NULL, *typestr = NULL;

        assert(loaded_image);

        efivar_set_time_usec(MAKE_GUID_PTR(LOADER), u"LoaderTimeInitUSec", init_usec);
        efivar_set(MAKE_GUID_PTR(LOADER), u"LoaderInfo", u"systemd-boot " GIT_VERSION, 0);

        infostr = xasprintf("%ls %u.%02u", ST->FirmwareVendor, ST->FirmwareRevision >> 16, ST->FirmwareRevision & 0xffff);
        efivar_set(MAKE_GUID_PTR(LOADER), u"LoaderFirmwareInfo", infostr, 0);

        typestr = xasprintf("UEFI %u.%02u", ST->Hdr.Revision >> 16, ST->Hdr.Revision & 0xffff);
        efivar_set(MAKE_GUID_PTR(LOADER), u"LoaderFirmwareType", typestr, 0);

        (void) efivar_set_uint64_le(MAKE_GUID_PTR(LOADER), u"LoaderFeatures", loader_features, 0);

        /* the filesystem path to this image, to prevent adding ourselves to the menu */
        efivar_set(MAKE_GUID_PTR(LOADER), u"LoaderImageIdentifier", loaded_image_path, 0);

        /* export the device path this image is started from */
        _cleanup_free_ char16_t *uuid = disk_get_part_uuid(loaded_image->DeviceHandle);
        if (uuid)
                efivar_set(MAKE_GUID_PTR(LOADER), u"LoaderDevicePartUUID", uuid, 0);
}

static void config_load_all_entries(
                Config *config,
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                const char16_t *loaded_image_path,
                EFI_FILE *root_dir) {

        assert(config);
        assert(loaded_image);
        assert(root_dir);

        config_load_defaults(config, root_dir);

        /* Scan /EFI/Linux/ directory */
        config_load_type2_entries(config, loaded_image->DeviceHandle, root_dir);

        /* Scan /loader/entries/\*.conf files */
        config_load_type1_entries(config, loaded_image->DeviceHandle, root_dir, loaded_image_path);

        /* Similar, but on any XBOOTLDR partition */
        config_load_xbootldr(config, loaded_image->DeviceHandle);

        /* Sort entries after version number */
        sort_array((void *) config->entries, sizeof *config->entries, config->n_entries, (compare_func_t) boot_entry_compare_indirect);

        /* If we find some well-known loaders, add them to the end of the list */
        config_add_entry_osx(config);
        config_add_entry_windows(config, loaded_image->DeviceHandle, root_dir);
        config_add_entry_loader_auto(config, loaded_image->DeviceHandle, root_dir, NULL,
                                     u"auto-efi-shell", 's', u"EFI Shell", u"\\shell" EFI_MACHINE_TYPE_NAME ".efi");
        config_add_entry_loader_auto(config, loaded_image->DeviceHandle, root_dir, loaded_image_path,
                                     u"auto-efi-default", '\0', u"EFI Default Loader", NULL);

        if (config->auto_firmware && FLAGS_SET(get_os_indications_supported(), EFI_OS_INDICATIONS_BOOT_TO_FW_UI)) {
                BootEntry *entry = xnew(BootEntry, 1);
                *entry = (BootEntry) {
                        .id = xstrdup16(u"auto-reboot-to-firmware-setup"),
                        .title = xstrdup16(u"Reboot Into Firmware Interface"),
                        .call = reboot_into_firmware,
                        .tries_done = -1,
                        .tries_left = -1,
                };
                config_add_entry(config, entry);
        }

        if (config->auto_poweroff) {
                BootEntry *entry = xnew(BootEntry, 1);
                *entry = (BootEntry) {
                        .id = xstrdup16(u"auto-poweroff"),
                        .title = xstrdup16(u"Power Off The System"),
                        .call = poweroff_system,
                        .tries_done = -1,
                        .tries_left = -1,
                };
                config_add_entry(config, entry);
        }

        if (config->auto_reboot) {
                BootEntry *entry = xnew(BootEntry, 1);
                *entry = (BootEntry) {
                        .id = xstrdup16(u"auto-reboot"),
                        .title = xstrdup16(u"Reboot The System"),
                        .call = reboot_system,
                        .tries_done = -1,
                        .tries_left = -1,
                };
                config_add_entry(config, entry);
        }

        /* Find secure boot signing keys and autoload them if configured.
         * Otherwise, create menu entries so that the user can load them manually.
         * If the secure-boot-enroll variable is set to no (the default), we do not
         * even search for keys on the ESP */
        if (config->secure_boot_enroll != ENROLL_OFF)
                secure_boot_discover_keys(config, root_dir);

        if (config->n_entries == 0)
                return;

        config_write_entries_to_variable(config);

        generate_boot_entry_titles(config);

        /* Select entry by configured pattern or EFI LoaderDefaultEntry= variable */
        config_select_default_entry(config);
}

static EFI_STATUS discover_root_dir(EFI_LOADED_IMAGE_PROTOCOL *loaded_image, EFI_FILE **ret_dir) {
        if (is_direct_boot(loaded_image->DeviceHandle))
                return vmm_open(&loaded_image->DeviceHandle, ret_dir);
        else
                return open_volume(loaded_image->DeviceHandle, ret_dir);
}

static EFI_STATUS run(EFI_HANDLE image) {
        EFI_LOADED_IMAGE_PROTOCOL *loaded_image;
        _cleanup_(file_closep) EFI_FILE *root_dir = NULL;
        _cleanup_(config_free) Config config = {};
        _cleanup_free_ char16_t *loaded_image_path = NULL;
        EFI_STATUS err;
        uint64_t init_usec;
        bool menu = false;

        init_usec = time_usec();

        /* Ask Shim to leave its protocol around, so that the stub can use it to validate PEs.
         * By default, Shim uninstalls its protocol when calling StartImage(). */
        shim_retain_protocol();

        err = BS->HandleProtocol(image, MAKE_GUID_PTR(EFI_LOADED_IMAGE_PROTOCOL), (void **) &loaded_image);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Error getting a LoadedImageProtocol handle: %m");

        (void) device_path_to_str(loaded_image->FilePath, &loaded_image_path);

        export_variables(loaded_image, loaded_image_path, init_usec);

        err = discover_root_dir(loaded_image, &root_dir);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Unable to open root directory: %m");

        (void) load_drivers(image, loaded_image, root_dir);

        config_load_all_entries(&config, loaded_image, loaded_image_path, root_dir);

        if (config.n_entries == 0)
                return log_error_status(
                                EFI_NOT_FOUND,
                                "No loader found. Configuration files in \\loader\\entries\\*.conf are needed.");

        /* select entry or show menu when key is pressed or timeout is set */
        if (config.force_menu || !IN_SET(config.timeout_sec, TIMEOUT_MENU_HIDDEN, TIMEOUT_MENU_DISABLED))
                menu = true;
        else if (config.timeout_sec != TIMEOUT_MENU_DISABLED) {
                uint64_t key;

                /* Block up to 100ms to give firmware time to get input working. */
                err = console_key_read(&key, 100 * 1000);
                if (err == EFI_SUCCESS) {
                        /* find matching key in boot entries */
                        size_t idx = entry_lookup_key(&config, config.idx_default, KEYCHAR(key));
                        if (idx != IDX_INVALID)
                                config.idx_default = idx;
                        else
                                menu = true;
                }
        }

        for (;;) {
                BootEntry *entry;

                entry = config.entries[config.idx_default];
                if (menu) {
                        efivar_set_time_usec(MAKE_GUID_PTR(LOADER), u"LoaderTimeMenuUSec", 0);
                        if (!menu_run(&config, &entry, loaded_image_path))
                                return EFI_SUCCESS;
                }

                /* if auto enrollment is activated, we try to load keys for the given entry. */
                if (entry->type == LOADER_SECURE_BOOT_KEYS && config.secure_boot_enroll != ENROLL_OFF) {
                        err = secure_boot_enroll_at(root_dir, entry->path, /*force=*/ true);
                        if (err != EFI_SUCCESS)
                                return err;
                        continue;
                }

                /* Run special entry like "reboot" now. Those that have a loader
                 * will be handled by image_start() instead. */
                if (entry->call && !entry->loader) {
                        entry->call();
                        continue;
                }

                (void) boot_entry_bump_counters(entry);
                save_selected_entry(&config, entry);

                /* Optionally, read a random seed off the ESP and pass it to the OS */
                (void) process_random_seed(root_dir);

                err = image_start(image, entry);
                if (err != EFI_SUCCESS)
                        return err;

                menu = true;
                config.timeout_sec = 0;
        }
}

DEFINE_EFI_MAIN_FUNCTION(run, "systemd-boot", /*wait_for_debugger=*/false);
