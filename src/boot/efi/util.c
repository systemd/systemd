/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <efi.h>
#include <efilib.h>
#if defined(__i386__) || defined(__x86_64__)
#  include <cpuid.h>
#endif

#include "ticks.h"
#include "util.h"

EFI_STATUS parse_boolean(const char *v, bool *b) {
        assert(b);

        if (!v)
                return EFI_INVALID_PARAMETER;

        if (streq8(v, "1") || streq8(v, "yes") || streq8(v, "y") || streq8(v, "true") || streq8(v, "t") ||
            streq8(v, "on")) {
                *b = true;
                return EFI_SUCCESS;
        }

        if (streq8(v, "0") || streq8(v, "no") || streq8(v, "n") || streq8(v, "false") || streq8(v, "f") ||
            streq8(v, "off")) {
                *b = false;
                return EFI_SUCCESS;
        }

        return EFI_INVALID_PARAMETER;
}

EFI_STATUS efivar_set_raw(const EFI_GUID *vendor, const char16_t *name, const void *buf, UINTN size, uint32_t flags) {
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

EFI_STATUS efivar_set_uint_string(const EFI_GUID *vendor, const char16_t *name, UINTN i, uint32_t flags) {
        char16_t str[32];

        assert(vendor);
        assert(name);

        /* Note that SPrint has no native sized length specifier and will always use ValueToString()
         * regardless of what sign we tell it to use. Therefore, UINTN_MAX will come out as -1 on
         * 64bit machines. */
        ValueToString(str, false, i);
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

EFI_STATUS efivar_get(const EFI_GUID *vendor, const char16_t *name, char16_t **value) {
        _cleanup_free_ char16_t *buf = NULL;
        EFI_STATUS err;
        char16_t *val;
        UINTN size;

        assert(vendor);
        assert(name);

        err = efivar_get_raw(vendor, name, (char **) &buf, &size);
        if (err != EFI_SUCCESS)
                return err;

        /* Make sure there are no incomplete characters in the buffer */
        if ((size % sizeof(char16_t)) != 0)
                return EFI_INVALID_PARAMETER;

        if (!value)
                return EFI_SUCCESS;

        /* Return buffer directly if it happens to be NUL terminated already */
        if (size >= sizeof(char16_t) && buf[size / sizeof(char16_t) - 1] == 0) {
                *value = TAKE_PTR(buf);
                return EFI_SUCCESS;
        }

        /* Make sure a terminating NUL is available at the end */
        val = xmalloc(size + sizeof(char16_t));

        memcpy(val, buf, size);
        val[size / sizeof(char16_t) - 1] = 0; /* NUL terminate */

        *value = val;
        return EFI_SUCCESS;
}

EFI_STATUS efivar_get_uint_string(const EFI_GUID *vendor, const char16_t *name, UINTN *i) {
        _cleanup_free_ char16_t *val = NULL;
        EFI_STATUS err;
        uint64_t u;

        assert(vendor);
        assert(name);
        assert(i);

        err = efivar_get(vendor, name, &val);
        if (err != EFI_SUCCESS)
                return err;

        if (!parse_number16(val, &u, NULL) || u > UINTN_MAX)
                return EFI_INVALID_PARAMETER;

        *i = u;
        return EFI_SUCCESS;
}

EFI_STATUS efivar_get_uint32_le(const EFI_GUID *vendor, const char16_t *name, uint32_t *ret) {
        _cleanup_free_ char *buf = NULL;
        UINTN size;
        EFI_STATUS err;

        assert(vendor);
        assert(name);

        err = efivar_get_raw(vendor, name, &buf, &size);
        if (err == EFI_SUCCESS && ret) {
                if (size != sizeof(uint32_t))
                        return EFI_BUFFER_TOO_SMALL;

                *ret = (uint32_t) buf[0] << 0U | (uint32_t) buf[1] << 8U | (uint32_t) buf[2] << 16U |
                        (uint32_t) buf[3] << 24U;
        }

        return err;
}

EFI_STATUS efivar_get_uint64_le(const EFI_GUID *vendor, const char16_t *name, uint64_t *ret) {
        _cleanup_free_ char *buf = NULL;
        UINTN size;
        EFI_STATUS err;

        assert(vendor);
        assert(name);

        err = efivar_get_raw(vendor, name, &buf, &size);
        if (err == EFI_SUCCESS && ret) {
                if (size != sizeof(uint64_t))
                        return EFI_BUFFER_TOO_SMALL;

                *ret = (uint64_t) buf[0] << 0U | (uint64_t) buf[1] << 8U | (uint64_t) buf[2] << 16U |
                        (uint64_t) buf[3] << 24U | (uint64_t) buf[4] << 32U | (uint64_t) buf[5] << 40U |
                        (uint64_t) buf[6] << 48U | (uint64_t) buf[7] << 56U;
        }

        return err;
}

EFI_STATUS efivar_get_raw(const EFI_GUID *vendor, const char16_t *name, char **buffer, UINTN *size) {
        _cleanup_free_ char *buf = NULL;
        UINTN l;
        EFI_STATUS err;

        assert(vendor);
        assert(name);

        l = sizeof(char16_t *) * EFI_MAXIMUM_VARIABLE_SIZE;
        buf = xmalloc(l);

        err = RT->GetVariable((char16_t *) name, (EFI_GUID *) vendor, NULL, &l, buf);
        if (err == EFI_SUCCESS) {

                if (buffer)
                        *buffer = TAKE_PTR(buf);

                if (size)
                        *size = l;
        }

        return err;
}

EFI_STATUS efivar_get_boolean_u8(const EFI_GUID *vendor, const char16_t *name, bool *ret) {
        _cleanup_free_ char *b = NULL;
        UINTN size;
        EFI_STATUS err;

        assert(vendor);
        assert(name);
        assert(ret);

        err = efivar_get_raw(vendor, name, &b, &size);
        if (err == EFI_SUCCESS)
                *ret = *b > 0;

        return err;
}

void efivar_set_time_usec(const EFI_GUID *vendor, const char16_t *name, uint64_t usec) {
        char16_t str[32];

        assert(vendor);
        assert(name);

        if (usec == 0)
                usec = time_usec();
        if (usec == 0)
                return;

        /* See comment on ValueToString in efivar_set_uint_string(). */
        ValueToString(str, false, usec);
        efivar_set(vendor, name, str, 0);
}

static int utf8_to_16(const char *stra, char16_t *c) {
        char16_t unichar;
        UINTN len;

        assert(stra);
        assert(c);

        if (!(stra[0] & 0x80))
                len = 1;
        else if ((stra[0] & 0xe0) == 0xc0)
                len = 2;
        else if ((stra[0] & 0xf0) == 0xe0)
                len = 3;
        else if ((stra[0] & 0xf8) == 0xf0)
                len = 4;
        else if ((stra[0] & 0xfc) == 0xf8)
                len = 5;
        else if ((stra[0] & 0xfe) == 0xfc)
                len = 6;
        else
                return -1;

        switch (len) {
        case 1:
                unichar = stra[0];
                break;
        case 2:
                unichar = stra[0] & 0x1f;
                break;
        case 3:
                unichar = stra[0] & 0x0f;
                break;
        case 4:
                unichar = stra[0] & 0x07;
                break;
        case 5:
                unichar = stra[0] & 0x03;
                break;
        case 6:
                unichar = stra[0] & 0x01;
                break;
        }

        for (UINTN i = 1; i < len; i++) {
                if ((stra[i] & 0xc0) != 0x80)
                        return -1;
                unichar <<= 6;
                unichar |= stra[i] & 0x3f;
        }

        *c = unichar;
        return len;
}

char16_t *xstra_to_str(const char *stra) {
        UINTN strlen;
        UINTN len;
        UINTN i;
        char16_t *str;

        assert(stra);

        len = strlen8(stra);
        str = xnew(char16_t, len + 1);

        strlen = 0;
        i = 0;
        while (i < len) {
                int utf8len;

                utf8len = utf8_to_16(stra + i, str + strlen);
                if (utf8len <= 0) {
                        /* invalid utf8 sequence, skip the garbage */
                        i++;
                        continue;
                }

                strlen++;
                i += utf8len;
        }
        str[strlen] = '\0';
        return str;
}

char16_t *xstra_to_path(const char *stra) {
        char16_t *str;
        UINTN strlen;
        UINTN len;
        UINTN i;

        assert(stra);

        len = strlen8(stra);
        str = xnew(char16_t, len + 2);

        str[0] = '\\';
        strlen = 1;
        i = 0;
        while (i < len) {
                int utf8len;

                utf8len = utf8_to_16(stra + i, str + strlen);
                if (utf8len <= 0) {
                        /* invalid utf8 sequence, skip the garbage */
                        i++;
                        continue;
                }

                if (str[strlen] == '/')
                        str[strlen] = '\\';
                if (str[strlen] == '\\' && str[strlen-1] == '\\') {
                        /* skip double slashes */
                        i += utf8len;
                        continue;
                }

                strlen++;
                i += utf8len;
        }
        str[strlen] = '\0';
        return str;
}

EFI_STATUS file_read(EFI_FILE *dir, const char16_t *name, UINTN off, UINTN size, char **ret, UINTN *ret_size) {
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

                err = get_file_info_harder(handle, &info, NULL);
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
        UINTN extra = size % sizeof(char16_t) + sizeof(char16_t);

        buf = xmalloc(size + extra);
        err = handle->Read(handle, &size, buf);
        if (err != EFI_SUCCESS)
                return err;

        /* Note that handle->Read() changes size to reflect the actually bytes read. */
        memset(buf + size, 0, extra);

        *ret = TAKE_PTR(buf);
        if (ret_size)
                *ret_size = size;

        return err;
}

void log_error_stall(const char16_t *fmt, ...) {
        va_list args;

        assert(fmt);

        int32_t attr = ST->ConOut->Mode->Attribute;
        ST->ConOut->SetAttribute(ST->ConOut, EFI_LIGHTRED|EFI_BACKGROUND_BLACK);

        if (ST->ConOut->Mode->CursorColumn > 0)
                Print(L"\n");

        va_start(args, fmt);
        VPrint(fmt, args);
        va_end(args);

        Print(L"\n");

        ST->ConOut->SetAttribute(ST->ConOut, attr);

        /* Give the user a chance to see the message. */
        BS->Stall(3 * 1000 * 1000);
}

EFI_STATUS log_oom(void) {
        log_error_stall(L"Out of memory.");
        return EFI_OUT_OF_RESOURCES;
}

void print_at(UINTN x, UINTN y, UINTN attr, const char16_t *str) {
        assert(str);
        ST->ConOut->SetCursorPosition(ST->ConOut, x, y);
        ST->ConOut->SetAttribute(ST->ConOut, attr);
        ST->ConOut->OutputString(ST->ConOut, (char16_t *) str);
}

void clear_screen(UINTN attr) {
        ST->ConOut->SetAttribute(ST->ConOut, attr);
        ST->ConOut->ClearScreen(ST->ConOut);
}

void sort_pointer_array(
                void **array,
                UINTN n_members,
                compare_pointer_func_t compare) {

        assert(array || n_members == 0);
        assert(compare);

        if (n_members <= 1)
                return;

        for (UINTN i = 1; i < n_members; i++) {
                UINTN k;
                void *entry = array[i];

                for (k = i; k > 0; k--) {
                        if (compare(array[k - 1], entry) <= 0)
                                break;

                        array[k] = array[k - 1];
                }

                array[k] = entry;
        }
}

EFI_STATUS get_file_info_harder(
                EFI_FILE *handle,
                EFI_FILE_INFO **ret,
                UINTN *ret_size) {

        UINTN size = offsetof(EFI_FILE_INFO, FileName) + 256;
        _cleanup_free_ EFI_FILE_INFO *fi = NULL;
        EFI_STATUS err;

        assert(handle);
        assert(ret);

        /* A lot like LibFileInfo() but with useful error propagation */

        fi = xmalloc(size);
        err = handle->GetInfo(handle, &GenericFileInfo, &size, fi);
        if (err == EFI_BUFFER_TOO_SMALL) {
                free(fi);
                fi = xmalloc(size);  /* GetInfo tells us the required size, let's use that now */
                err = handle->GetInfo(handle, &GenericFileInfo, &size, fi);
        }

        if (err != EFI_SUCCESS)
                return err;

        *ret = TAKE_PTR(fi);

        if (ret_size)
                *ret_size = size;

        return EFI_SUCCESS;
}

EFI_STATUS readdir_harder(
                EFI_FILE *handle,
                EFI_FILE_INFO **buffer,
                UINTN *buffer_size) {

        EFI_STATUS err;
        UINTN sz;

        assert(handle);
        assert(buffer);
        assert(buffer_size);

        /* buffer/buffer_size are both in and output parameters. Should be zero-initialized initially, and
         * the specified buffer needs to be freed by caller, after final use. */

        if (!*buffer) {
                /* Some broken firmware violates the EFI spec by still advancing the readdir
                 * position when returning EFI_BUFFER_TOO_SMALL, effectively skipping over any files when
                 * the buffer was too small. Therefore, start with a buffer that should handle FAT32 max
                 * file name length.
                 * As a side effect, most readdir_harder() calls will now be slightly faster. */
                sz = sizeof(EFI_FILE_INFO) + 256 * sizeof(char16_t);
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

        err = get_file_info_harder(dir, &file_info, NULL);
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

        err = efivar_get_uint64_le(EFI_GLOBAL_GUID, L"OsIndicationsSupported", &osind);
        if (err != EFI_SUCCESS)
                return 0;

        return osind;
}

#ifdef EFI_DEBUG
__attribute__((noinline)) void debug_break(void) {
        /* This is a poor programmer's breakpoint to wait until a debugger
         * has attached to us. Just "set variable wait = 0" or "return" to continue. */
        volatile bool wait = true;
        while (wait)
                /* Prefer asm based stalling so that gdb has a source location to present. */
#if defined(__i386__) || defined(__x86_64__)
                asm volatile("pause");
#elif defined(__aarch64__)
                asm volatile("wfi");
#else
                BS->Stall(5000);
#endif
}
#endif


#ifdef EFI_DEBUG
void hexdump(const char16_t *prefix, const void *data, UINTN size) {
        static const char hex[16] = "0123456789abcdef";
        _cleanup_free_ char16_t *buf = NULL;
        const uint8_t *d = data;

        assert(prefix);
        assert(data || size == 0);

        /* Debugging helper — please keep this around, even if not used */

        buf = xnew(char16_t, size*2+1);

        for (UINTN i = 0; i < size; i++) {
                buf[i*2] = hex[d[i] >> 4];
                buf[i*2+1] = hex[d[i] & 0x0F];
        }

        buf[size*2] = 0;

        log_error_stall(L"%s[%" PRIuN "]: %s", prefix, size, buf);
}
#endif

#if defined(__i386__) || defined(__x86_64__)
static inline uint8_t inb(uint16_t port) {
        uint8_t value;
        asm volatile("inb %1, %0" : "=a"(value) : "Nd"(port));
        return value;
}

static inline void outb(uint16_t port, uint8_t value) {
        asm volatile("outb %0, %1" : : "a"(value), "Nd"(port));
}

void beep(UINTN beep_count) {
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

        err = BS->HandleProtocol(device, &FileSystemProtocol, (void **) &volume);
        if (err != EFI_SUCCESS)
                return err;

        err = volume->OpenVolume(volume, &file);
        if (err != EFI_SUCCESS)
                return err;

        *ret_file = file;
        return EFI_SUCCESS;
}

EFI_STATUS make_file_device_path(EFI_HANDLE device, const char16_t *file, EFI_DEVICE_PATH **ret_dp) {
        EFI_STATUS err;
        EFI_DEVICE_PATH *dp;

        assert(file);
        assert(ret_dp);

        err = BS->HandleProtocol(device, &DevicePathProtocol, (void **) &dp);
        if (err != EFI_SUCCESS)
                return err;

        EFI_DEVICE_PATH *end_node = dp;
        while (!IsDevicePathEnd(end_node))
                end_node = NextDevicePathNode(end_node);

        size_t file_size = strsize16(file);
        size_t dp_size = (uint8_t *) end_node - (uint8_t *) dp;

        /* Make a copy that can also hold a file media device path. */
        *ret_dp = xmalloc(dp_size + file_size + SIZE_OF_FILEPATH_DEVICE_PATH + END_DEVICE_PATH_LENGTH);
        dp = mempcpy(*ret_dp, dp, dp_size);

        /* Replace end node with file media device path. Use memcpy() in case dp is unaligned (if accessed as
         * FILEPATH_DEVICE_PATH). */
        dp->Type = MEDIA_DEVICE_PATH;
        dp->SubType = MEDIA_FILEPATH_DP;
        memcpy((uint8_t *) dp + offsetof(FILEPATH_DEVICE_PATH, PathName), file, file_size);
        SetDevicePathNodeLength(dp, offsetof(FILEPATH_DEVICE_PATH, PathName) + file_size);

        dp = NextDevicePathNode(dp);
        SetDevicePathEndNode(dp);
        return EFI_SUCCESS;
}

EFI_STATUS device_path_to_str(const EFI_DEVICE_PATH *dp, char16_t **ret) {
        EFI_DEVICE_PATH_TO_TEXT_PROTOCOL *dp_to_text;
        EFI_STATUS err;
        _cleanup_free_ char16_t *str = NULL;

        assert(dp);
        assert(ret);

        err = BS->LocateProtocol(&(EFI_GUID) EFI_DEVICE_PATH_TO_TEXT_PROTOCOL_GUID, NULL, (void **) &dp_to_text);
        if (err != EFI_SUCCESS) {
                /* If the device path to text protocol is not available we can still do a best-effort attempt
                 * to convert it ourselves if we are given filepath-only device path. */

                size_t size = 0;
                for (const EFI_DEVICE_PATH *node = dp; !IsDevicePathEnd(node);
                     node = NextDevicePathNode(node)) {

                        if (DevicePathType(node) != MEDIA_DEVICE_PATH ||
                            DevicePathSubType(node) != MEDIA_FILEPATH_DP)
                                return err;

                        size_t path_size = DevicePathNodeLength(node);
                        if (path_size <= offsetof(FILEPATH_DEVICE_PATH, PathName) || path_size % sizeof(char16_t))
                                return EFI_INVALID_PARAMETER;
                        path_size -= offsetof(FILEPATH_DEVICE_PATH, PathName);

                        _cleanup_free_ char16_t *old = str;
                        str = xmalloc(size + path_size);
                        if (old) {
                                memcpy(str, old, size);
                                str[size / sizeof(char16_t) - 1] = '\\';
                        }

                        memcpy(str + (size / sizeof(char16_t)),
                               ((uint8_t *) node) + offsetof(FILEPATH_DEVICE_PATH, PathName),
                               path_size);
                        size += path_size;
                }

                *ret = TAKE_PTR(str);
                return EFI_SUCCESS;
        }

        str = dp_to_text->ConvertDevicePathToText(dp, false, false);
        if (!str)
                return EFI_OUT_OF_RESOURCES;

        *ret = TAKE_PTR(str);
        return EFI_SUCCESS;
}

#if defined(__i386__) || defined(__x86_64__)
bool in_hypervisor(void) {
        uint32_t eax, ebx, ecx, edx;

        /* This is a dumbed down version of src/basic/virt.c's detect_vm() that safely works in the UEFI
         * environment. */

        if (__get_cpuid(1, &eax, &ebx, &ecx, &edx) == 0)
                return false;

        return !!(ecx & 0x80000000U);
}
#endif
