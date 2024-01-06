/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "device-path-util.h"
#include "memory-util-fundamental.h"
#include "proto/device-path.h"
#include "proto/simple-text-io.h"
#include "ticks.h"
#include "util.h"
#include "version.h"

EFI_STATUS efivar_set_raw(const EFI_GUID *vendor, const char16_t *name, const void *buf, size_t size, uint32_t flags) {
        assert(vendor);
        assert(name);
        assert(buf || size == 0);

        flags |= EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS;
        return RT->SetVariable((char16_t *) name, (EFI_GUID *) vendor, flags, size, (void *) buf);
}

EFI_STATUS efivar_set(const EFI_GUID *vendor, const char16_t *name, const char16_t *value, uint32_t flags) {
        assert(vendor);
        assert(name);

        return efivar_set_raw(vendor, name, value, value ? strsize16(value) : 0, flags);
}

EFI_STATUS efivar_set_uint_string(const EFI_GUID *vendor, const char16_t *name, size_t i, uint32_t flags) {
        assert(vendor);
        assert(name);

        _cleanup_free_ char16_t *str = xasprintf("%zu", i);
        return efivar_set(vendor, name, str, flags);
}

EFI_STATUS efivar_set_uint32_le(const EFI_GUID *vendor, const char16_t *name, uint32_t value, uint32_t flags) {
        uint8_t buf[4];

        assert(vendor);
        assert(name);

        buf[0] = (uint8_t)(value >> 0U & 0xFF);
        buf[1] = (uint8_t)(value >> 8U & 0xFF);
        buf[2] = (uint8_t)(value >> 16U & 0xFF);
        buf[3] = (uint8_t)(value >> 24U & 0xFF);

        return efivar_set_raw(vendor, name, buf, sizeof(buf), flags);
}

EFI_STATUS efivar_set_uint64_le(const EFI_GUID *vendor, const char16_t *name, uint64_t value, uint32_t flags) {
        uint8_t buf[8];

        assert(vendor);
        assert(name);

        buf[0] = (uint8_t)(value >> 0U & 0xFF);
        buf[1] = (uint8_t)(value >> 8U & 0xFF);
        buf[2] = (uint8_t)(value >> 16U & 0xFF);
        buf[3] = (uint8_t)(value >> 24U & 0xFF);
        buf[4] = (uint8_t)(value >> 32U & 0xFF);
        buf[5] = (uint8_t)(value >> 40U & 0xFF);
        buf[6] = (uint8_t)(value >> 48U & 0xFF);
        buf[7] = (uint8_t)(value >> 56U & 0xFF);

        return efivar_set_raw(vendor, name, buf, sizeof(buf), flags);
}

EFI_STATUS efivar_unset(const EFI_GUID *vendor, const char16_t *name, uint32_t flags) {
        EFI_STATUS err;

        assert(vendor);
        assert(name);

        /* We could be wiping a non-volatile variable here and the spec makes no guarantees that won't incur
         * in an extra write (and thus wear out). So check and clear only if needed. */
        err = efivar_get_raw(vendor, name, NULL, NULL);
        if (err == EFI_SUCCESS)
                return efivar_set_raw(vendor, name, NULL, 0, flags);

        return err;
}

EFI_STATUS efivar_get(const EFI_GUID *vendor, const char16_t *name, char16_t **ret) {
        _cleanup_free_ char16_t *buf = NULL;
        EFI_STATUS err;
        char16_t *val;
        size_t size;

        assert(vendor);
        assert(name);

        err = efivar_get_raw(vendor, name, &buf, &size);
        if (err != EFI_SUCCESS)
                return err;

        /* Make sure there are no incomplete characters in the buffer */
        if ((size % sizeof(char16_t)) != 0)
                return EFI_INVALID_PARAMETER;

        if (!ret)
                return EFI_SUCCESS;

        /* Return buffer directly if it happens to be NUL terminated already */
        if (size >= sizeof(char16_t) && buf[size / sizeof(char16_t) - 1] == 0) {
                *ret = TAKE_PTR(buf);
                return EFI_SUCCESS;
        }

        /* Make sure a terminating NUL is available at the end */
        val = xmalloc(size + sizeof(char16_t));

        memcpy(val, buf, size);
        val[size / sizeof(char16_t) - 1] = 0; /* NUL terminate */

        *ret = val;
        return EFI_SUCCESS;
}

EFI_STATUS efivar_get_uint_string(const EFI_GUID *vendor, const char16_t *name, size_t *ret) {
        _cleanup_free_ char16_t *val = NULL;
        EFI_STATUS err;
        uint64_t u;

        assert(vendor);
        assert(name);

        err = efivar_get(vendor, name, &val);
        if (err != EFI_SUCCESS)
                return err;

        if (!parse_number16(val, &u, NULL) || u > SIZE_MAX)
                return EFI_INVALID_PARAMETER;

        if (ret)
                *ret = u;
        return EFI_SUCCESS;
}

EFI_STATUS efivar_get_uint32_le(const EFI_GUID *vendor, const char16_t *name, uint32_t *ret) {
        _cleanup_free_ uint8_t *buf = NULL;
        size_t size;
        EFI_STATUS err;

        assert(vendor);
        assert(name);

        err = efivar_get_raw(vendor, name, &buf, &size);
        if (err != EFI_SUCCESS)
                return err;

        if (size != sizeof(uint32_t))
                return EFI_BUFFER_TOO_SMALL;

        if (ret)
                *ret = (uint32_t) buf[0] << 0U | (uint32_t) buf[1] << 8U | (uint32_t) buf[2] << 16U |
                        (uint32_t) buf[3] << 24U;

        return EFI_SUCCESS;
}

EFI_STATUS efivar_get_uint64_le(const EFI_GUID *vendor, const char16_t *name, uint64_t *ret) {
        _cleanup_free_ uint8_t *buf = NULL;
        size_t size;
        EFI_STATUS err;

        assert(vendor);
        assert(name);

        err = efivar_get_raw(vendor, name, &buf, &size);
        if (err != EFI_SUCCESS)
                return err;

        if (size != sizeof(uint64_t))
                return EFI_BUFFER_TOO_SMALL;

        if (ret)
                *ret = (uint64_t) buf[0] << 0U | (uint64_t) buf[1] << 8U | (uint64_t) buf[2] << 16U |
                        (uint64_t) buf[3] << 24U | (uint64_t) buf[4] << 32U | (uint64_t) buf[5] << 40U |
                        (uint64_t) buf[6] << 48U | (uint64_t) buf[7] << 56U;

        return EFI_SUCCESS;
}

EFI_STATUS efivar_get_raw(const EFI_GUID *vendor, const char16_t *name, void **ret, size_t *ret_size) {
        EFI_STATUS err;

        assert(vendor);
        assert(name);

        size_t size = 0;
        err = RT->GetVariable((char16_t *) name, (EFI_GUID *) vendor, NULL, &size, NULL);
        if (err != EFI_BUFFER_TOO_SMALL)
                return err;

        _cleanup_free_ void *buf = xmalloc(size);
        err = RT->GetVariable((char16_t *) name, (EFI_GUID *) vendor, NULL, &size, buf);
        if (err != EFI_SUCCESS)
                return err;

        if (ret)
                *ret = TAKE_PTR(buf);
        if (ret_size)
                *ret_size = size;

        return EFI_SUCCESS;
}

EFI_STATUS efivar_get_boolean_u8(const EFI_GUID *vendor, const char16_t *name, bool *ret) {
        _cleanup_free_ uint8_t *b = NULL;
        size_t size;
        EFI_STATUS err;

        assert(vendor);
        assert(name);

        err = efivar_get_raw(vendor, name, &b, &size);
        if (err != EFI_SUCCESS)
                return err;

        if (ret)
                *ret = !!*b;

        return EFI_SUCCESS;
}

void efivar_set_time_usec(const EFI_GUID *vendor, const char16_t *name, uint64_t usec) {
        assert(vendor);
        assert(name);

        if (usec == 0)
                usec = time_usec();
        if (usec == 0)
                return;

        _cleanup_free_ char16_t *str = xasprintf("%" PRIu64, usec);
        efivar_set(vendor, name, str, 0);
}

void convert_efi_path(char16_t *path) {
        assert(path);

        for (size_t i = 0, fixed = 0;; i++) {
                /* Fix device path node separator. */
                path[fixed] = (path[i] == '/') ? '\\' : path[i];

                /* Double '\' is not allowed in EFI file paths. */
                if (fixed > 0 && path[fixed - 1] == '\\' && path[fixed] == '\\')
                        continue;

                if (path[i] == '\0')
                        break;

                fixed++;
        }
}

char16_t *xstr8_to_path(const char *str8) {
        assert(str8);
        char16_t *path = xstr8_to_16(str8);
        convert_efi_path(path);
        return path;
}

static bool shall_be_whitespace(char16_t c) {
        return c <= 0x20U || c == 0x7FU; /* All control characters + space */
}

char16_t* mangle_stub_cmdline(char16_t *cmdline) {
        char16_t *p, *q, *e;

        if (!cmdline)
                return cmdline;

        p = q = cmdline;

        /* Skip initial whitespace */
        while (shall_be_whitespace(*p))
                p++;

        /* Turn inner control characters into proper spaces */
        for (e = p; *p != 0; p++) {
                if (shall_be_whitespace(*p)) {
                        *(q++) = ' ';
                        continue;
                }

                *(q++) = *p;
                e = q; /* remember last non-whitespace char */
        }

        /* Chop off trailing whitespace */
        *e = 0;
        return cmdline;
}

EFI_STATUS chunked_read(EFI_FILE *file, size_t *size, void *buf) {
        EFI_STATUS err;

        assert(file);
        assert(size);
        assert(buf);

        /* This is a drop-in replacement for EFI_FILE->Read() with the same API behavior.
         * Some broken firmwares cannot handle large file reads and will instead return
         * an error. As a workaround, read such files in small chunks.
         * Note that we cannot just try reading the whole file first on such firmware as
         * that will permanently break the handle even if it is re-opened.
         *
         * https://github.com/systemd/systemd/issues/25911 */

        if (*size == 0)
                return EFI_SUCCESS;

        size_t read = 0, remaining = *size;
        while (remaining > 0) {
                size_t chunk = MIN(1024U * 1024U, remaining);

                err = file->Read(file, &chunk, (uint8_t *) buf + read);
                if (err != EFI_SUCCESS)
                        return err;
                if (chunk == 0)
                        /* Caller requested more bytes than are in file. */
                        break;

                assert(chunk <= remaining);
                read += chunk;
                remaining -= chunk;
        }

        *size = read;
        return EFI_SUCCESS;
}

EFI_STATUS file_read(EFI_FILE *dir, const char16_t *name, size_t off, size_t size, char **ret, size_t *ret_size) {
        _cleanup_(file_closep) EFI_FILE *handle = NULL;
        _cleanup_free_ char *buf = NULL;
        EFI_STATUS err;

        assert(dir);
        assert(name);
        assert(ret);

        err = dir->Open(dir, &handle, (char16_t*) name, EFI_FILE_MODE_READ, 0ULL);
        if (err != EFI_SUCCESS)
                return err;

        if (size == 0) {
                _cleanup_free_ EFI_FILE_INFO *info = NULL;

                err = get_file_info(handle, &info, NULL);
                if (err != EFI_SUCCESS)
                        return err;

                size = info->FileSize;
        }

        if (off > 0) {
                err = handle->SetPosition(handle, off);
                if (err != EFI_SUCCESS)
                        return err;
        }

        /* Allocate some extra bytes to guarantee the result is NUL-terminated for char and char16_t strings. */
        size_t extra = size % sizeof(char16_t) + sizeof(char16_t);

        buf = xmalloc(size + extra);
        err = chunked_read(handle, &size, buf);
        if (err != EFI_SUCCESS)
                return err;

        /* Note that chunked_read() changes size to reflect the actual bytes read. */
        memzero(buf + size, extra);

        *ret = TAKE_PTR(buf);
        if (ret_size)
                *ret_size = size;

        return err;
}

void print_at(size_t x, size_t y, size_t attr, const char16_t *str) {
        assert(str);
        ST->ConOut->SetCursorPosition(ST->ConOut, x, y);
        ST->ConOut->SetAttribute(ST->ConOut, attr);
        ST->ConOut->OutputString(ST->ConOut, (char16_t *) str);
}

void clear_screen(size_t attr) {
        log_wait();
        ST->ConOut->SetAttribute(ST->ConOut, attr);
        ST->ConOut->ClearScreen(ST->ConOut);
}

void sort_pointer_array(
                void **array,
                size_t n_members,
                compare_pointer_func_t compare) {

        assert(array || n_members == 0);
        assert(compare);

        if (n_members <= 1)
                return;

        for (size_t i = 1; i < n_members; i++) {
                size_t k;
                void *entry = array[i];

                for (k = i; k > 0; k--) {
                        if (compare(array[k - 1], entry) <= 0)
                                break;

                        array[k] = array[k - 1];
                }

                array[k] = entry;
        }
}

EFI_STATUS get_file_info(EFI_FILE *handle, EFI_FILE_INFO **ret, size_t *ret_size) {
        size_t size = EFI_FILE_INFO_MIN_SIZE;
        _cleanup_free_ EFI_FILE_INFO *fi = NULL;
        EFI_STATUS err;

        assert(handle);
        assert(ret);

        fi = xmalloc(size);
        err = handle->GetInfo(handle, MAKE_GUID_PTR(EFI_FILE_INFO), &size, fi);
        if (err == EFI_BUFFER_TOO_SMALL) {
                free(fi);
                fi = xmalloc(size);  /* GetInfo tells us the required size, let's use that now */
                err = handle->GetInfo(handle, MAKE_GUID_PTR(EFI_FILE_INFO), &size, fi);
        }

        if (err != EFI_SUCCESS)
                return err;

        *ret = TAKE_PTR(fi);

        if (ret_size)
                *ret_size = size;

        return EFI_SUCCESS;
}

EFI_STATUS readdir(
                EFI_FILE *handle,
                EFI_FILE_INFO **buffer,
                size_t *buffer_size) {

        EFI_STATUS err;
        size_t sz;

        assert(handle);
        assert(buffer);
        assert(buffer_size);

        /* buffer/buffer_size are both in and output parameters. Should be zero-initialized initially, and
         * the specified buffer needs to be freed by caller, after final use. */

        if (!*buffer) {
                sz = EFI_FILE_INFO_MIN_SIZE;
                *buffer = xmalloc(sz);
                *buffer_size = sz;
        } else
                sz = *buffer_size;

        err = handle->Read(handle, &sz, *buffer);
        if (err == EFI_BUFFER_TOO_SMALL) {
                free(*buffer);
                *buffer = xmalloc(sz);
                *buffer_size = sz;
                err = handle->Read(handle, &sz, *buffer);
        }
        if (err != EFI_SUCCESS)
                return err;

        if (sz == 0) {
                /* End of directory */
                free(*buffer);
                *buffer = NULL;
                *buffer_size = 0;
        }

        return EFI_SUCCESS;
}

bool is_ascii(const char16_t *f) {
        if (!f)
                return false;

        for (; *f != 0; f++)
                if (*f > 127)
                        return false;

        return true;
}

char16_t **strv_free(char16_t **v) {
        if (!v)
                return NULL;

        for (char16_t **i = v; *i; i++)
                free(*i);

        free(v);
        return NULL;
}

EFI_STATUS open_directory(
                EFI_FILE *root,
                const char16_t *path,
                EFI_FILE **ret) {

        _cleanup_(file_closep) EFI_FILE *dir = NULL;
        _cleanup_free_ EFI_FILE_INFO *file_info = NULL;
        EFI_STATUS err;

        assert(root);

        /* Opens a file, and then verifies it is actually a directory */

        err = root->Open(root, &dir, (char16_t *) path, EFI_FILE_MODE_READ, 0);
        if (err != EFI_SUCCESS)
                return err;

        err = get_file_info(dir, &file_info, NULL);
        if (err != EFI_SUCCESS)
                return err;
        if (!FLAGS_SET(file_info->Attribute, EFI_FILE_DIRECTORY))
                return EFI_LOAD_ERROR;

        *ret = TAKE_PTR(dir);
        return EFI_SUCCESS;
}

uint64_t get_os_indications_supported(void) {
        uint64_t osind;
        EFI_STATUS err;

        /* Returns the supported OS indications. If we can't acquire it, returns a zeroed out mask, i.e. no
         * supported features. */

        err = efivar_get_uint64_le(MAKE_GUID_PTR(EFI_GLOBAL_VARIABLE), u"OsIndicationsSupported", &osind);
        if (err != EFI_SUCCESS)
                return 0;

        return osind;
}

__attribute__((noinline)) void notify_debugger(const char *identity, volatile bool wait) {
#ifdef EFI_DEBUG
        printf("%s@%p %s\n", identity, __executable_start, GIT_VERSION);
        if (wait)
                printf("Waiting for debugger to attach...\n");

        /* This is a poor programmer's breakpoint to wait until a debugger
         * has attached to us. Just "set variable wait = 0" or "return" to continue. */
        while (wait)
                /* Prefer asm based stalling so that gdb has a source location to present. */
#  if defined(__i386__) || defined(__x86_64__)
                asm volatile("pause");
#  elif defined(__aarch64__)
                asm volatile("wfi");
#  else
                BS->Stall(5000);
#  endif
#endif
}

#if defined(__i386__) || defined(__x86_64__)
static uint8_t inb(uint16_t port) {
        uint8_t value;
        asm volatile("inb %1, %0" : "=a"(value) : "Nd"(port));
        return value;
}

static void outb(uint16_t port, uint8_t value) {
        asm volatile("outb %0, %1" : : "a"(value), "Nd"(port));
}

void beep(unsigned beep_count) {
        enum {
                PITCH                = 500,
                BEEP_DURATION_USEC   = 100 * 1000,
                WAIT_DURATION_USEC   = 400 * 1000,

                PIT_FREQUENCY        = 0x1234dd,
                SPEAKER_CONTROL_PORT = 0x61,
                SPEAKER_ON_MASK      = 0x03,
                TIMER_PORT_MAGIC     = 0xB6,
                TIMER_CONTROL_PORT   = 0x43,
                TIMER_CONTROL2_PORT  = 0x42,
        };

        /* Set frequency. */
        uint32_t counter = PIT_FREQUENCY / PITCH;
        outb(TIMER_CONTROL_PORT, TIMER_PORT_MAGIC);
        outb(TIMER_CONTROL2_PORT, counter & 0xFF);
        outb(TIMER_CONTROL2_PORT, (counter >> 8) & 0xFF);

        uint8_t value = inb(SPEAKER_CONTROL_PORT);

        while (beep_count > 0) {
                /* Turn speaker on. */
                value |= SPEAKER_ON_MASK;
                outb(SPEAKER_CONTROL_PORT, value);

                BS->Stall(BEEP_DURATION_USEC);

                /* Turn speaker off. */
                value &= ~SPEAKER_ON_MASK;
                outb(SPEAKER_CONTROL_PORT, value);

                beep_count--;
                if (beep_count > 0)
                        BS->Stall(WAIT_DURATION_USEC);
        }
}
#endif

EFI_STATUS open_volume(EFI_HANDLE device, EFI_FILE **ret_file) {
        EFI_STATUS err;
        EFI_FILE *file;
        EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *volume;

        assert(ret_file);

        err = BS->HandleProtocol(device, MAKE_GUID_PTR(EFI_SIMPLE_FILE_SYSTEM_PROTOCOL), (void **) &volume);
        if (err != EFI_SUCCESS)
                return err;

        err = volume->OpenVolume(volume, &file);
        if (err != EFI_SUCCESS)
                return err;

        *ret_file = file;
        return EFI_SUCCESS;
}

void *find_configuration_table(const EFI_GUID *guid) {
        for (size_t i = 0; i < ST->NumberOfTableEntries; i++)
                if (efi_guid_equal(&ST->ConfigurationTable[i].VendorGuid, guid))
                        return ST->ConfigurationTable[i].VendorTable;

        return NULL;
}

static void remove_boot_count(char16_t *path) {
        char16_t *prefix_end;
        const char16_t *tail;
        uint64_t ignored;

        assert(path);

        prefix_end = strchr16(path, '+');
        if (!prefix_end)
                return;

        tail = prefix_end + 1;

        if (!parse_number16(tail, &ignored, &tail))
                return;

        if (*tail == '-') {
                ++tail;
                if (!parse_number16(tail, &ignored, &tail))
                        return;
        }

        if (!IN_SET(*tail, '\0', '.'))
                return;

        strcpy16(prefix_end, tail);
}

char16_t *get_extra_dir(const EFI_DEVICE_PATH *file_path) {
        if (!file_path)
                return NULL;

        /* A device path is allowed to have more than one file path node. If that is the case they are
         * supposed to be concatenated. Unfortunately, the device path to text protocol simply converts the
         * nodes individually and then combines those with the usual '/' for device path nodes. But this does
         * not create a legal EFI file path that the file protocol can use. */

        /* Make sure we really only got file paths. */
        for (const EFI_DEVICE_PATH *node = file_path; !device_path_is_end(node);
             node = device_path_next_node(node))
                if (node->Type != MEDIA_DEVICE_PATH || node->SubType != MEDIA_FILEPATH_DP)
                        return NULL;

        _cleanup_free_ char16_t *file_path_str = NULL;
        if (device_path_to_str(file_path, &file_path_str) != EFI_SUCCESS)
                return NULL;

        convert_efi_path(file_path_str);
        remove_boot_count(file_path_str);
        return xasprintf("%ls.extra.d", file_path_str);
}
