/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "efi-string.h"
#include "efivars.h"
#include "ticks.h"
#include "util.h"

EFI_STATUS efivar_set_raw(const EFI_GUID *vendor, const char16_t *name, const void *buf, size_t size, uint32_t flags) {
        assert(vendor);
        assert(name);
        assert(buf || size == 0);

        flags |= EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS;
        return RT->SetVariable((char16_t *) name, (EFI_GUID *) vendor, flags, size, (void *) buf);
}

EFI_STATUS efivar_set_str16(const EFI_GUID *vendor, const char16_t *name, const char16_t *value, uint32_t flags) {
        assert(vendor);
        assert(name);

        return efivar_set_raw(vendor, name, value, value ? strsize16(value) : 0, flags);
}

EFI_STATUS efivar_set_uint64_str16(const EFI_GUID *vendor, const char16_t *name, uint64_t i, uint32_t flags) {
        assert(vendor);
        assert(name);

        _cleanup_free_ char16_t *str = xasprintf("%" PRIu64, i);
        return efivar_set_str16(vendor, name, str, flags);
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

EFI_STATUS efivar_get_str16(const EFI_GUID *vendor, const char16_t *name, char16_t **ret) {
        _cleanup_free_ char16_t *buf = NULL;
        EFI_STATUS err;
        char16_t *val;
        size_t size;

        assert(vendor);
        assert(name);

        err = efivar_get_raw(vendor, name, (void**) &buf, &size);
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

EFI_STATUS efivar_get_uint64_str16(const EFI_GUID *vendor, const char16_t *name, uint64_t *ret) {
        EFI_STATUS err;

        assert(vendor);
        assert(name);

        _cleanup_free_ char16_t *val = NULL;
        err = efivar_get_str16(vendor, name, &val);
        if (err != EFI_SUCCESS)
                return err;

        uint64_t u;
        if (!parse_number16(val, &u, NULL))
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

        err = efivar_get_raw(vendor, name, (void**) &buf, &size);
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

        err = efivar_get_raw(vendor, name, (void**) &buf, &size);
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

        err = efivar_get_raw(vendor, name, (void**) &b, &size);
        if (err != EFI_SUCCESS)
                return err;

        if (ret)
                *ret = *b > 0;

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
        efivar_set_str16(vendor, name, str, 0);
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
