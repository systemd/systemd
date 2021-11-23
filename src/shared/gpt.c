/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "gpt.h"
#include "string-util.h"
#include "utf8.h"

/* Gently push people towards defining GPT type UUIDs for all architectures we know */
#if !defined(GPT_ROOT_NATIVE) ||                                        \
        !defined(GPT_ROOT_NATIVE_VERITY) ||                             \
        !defined(GPT_ROOT_NATIVE_VERITY_SIG) ||                         \
        !defined(GPT_USR_NATIVE) ||                                     \
        !defined(GPT_USR_NATIVE_VERITY) ||                              \
        !defined(GPT_USR_NATIVE_VERITY_SIG)
#pragma message "Please define GPT partition types for your architecture."
#endif

#define _GPT_ARCH_SEXTET(arch, name)                                   \
        { GPT_ROOT_##arch,              "root-" name,               ARCHITECTURE_##arch },  \
        { GPT_ROOT_##arch##_VERITY,     "root-" name "-verity",     ARCHITECTURE_##arch },  \
        { GPT_ROOT_##arch##_VERITY_SIG, "root-" name "-verity-sig", ARCHITECTURE_##arch },  \
        { GPT_USR_##arch,               "usr-" name,                ARCHITECTURE_##arch },  \
        { GPT_USR_##arch##_VERITY,      "usr-" name "-verity",      ARCHITECTURE_##arch },  \
        { GPT_USR_##arch##_VERITY_SIG,  "usr-" name "-verity-sig",  ARCHITECTURE_##arch }

const GptPartitionType gpt_partition_type_table[] = {
        _GPT_ARCH_SEXTET(ALPHA,       "alpha"),
        _GPT_ARCH_SEXTET(ARC,         "arc"),
        _GPT_ARCH_SEXTET(ARM,         "arm"),
        _GPT_ARCH_SEXTET(ARM64,       "arm64"),
        _GPT_ARCH_SEXTET(IA64,        "ia64"),

        // TODO: Replace with `_GPT_ARCH_SEXTET(LOONGARCH64, "loongarch64")` once
        // https://github.com/systemd/systemd/pull/21288 is merged. */
        { GPT_ROOT_LOONGARCH64,            "root-loongarch64",            _ARCHITECTURE_INVALID },
        { GPT_ROOT_LOONGARCH64_VERITY,     "root-loongarch64-verity",     _ARCHITECTURE_INVALID },
        { GPT_ROOT_LOONGARCH64_VERITY_SIG, "root-loongarch64-verity-sig", _ARCHITECTURE_INVALID },
        { GPT_USR_LOONGARCH64,             "usr-loongarch64",             _ARCHITECTURE_INVALID },
        { GPT_USR_LOONGARCH64_VERITY,      "usr-loongarch64-verity",      _ARCHITECTURE_INVALID },
        { GPT_USR_LOONGARCH64_VERITY_SIG,  "usr-loongarch64-verity-sig",  _ARCHITECTURE_INVALID },

        _GPT_ARCH_SEXTET(MIPS_LE,     "mips-le"),
        _GPT_ARCH_SEXTET(MIPS64_LE,   "mips64-le"),
        _GPT_ARCH_SEXTET(PPC,         "ppc"),
        _GPT_ARCH_SEXTET(PPC64,       "ppc64"),
        _GPT_ARCH_SEXTET(PPC64_LE,     "ppc64-le"),
        _GPT_ARCH_SEXTET(RISCV32,     "riscv32"),
        _GPT_ARCH_SEXTET(RISCV64,     "riscv64"),
        _GPT_ARCH_SEXTET(S390,        "s390"),
        _GPT_ARCH_SEXTET(S390X,       "s390x"),
        _GPT_ARCH_SEXTET(TILEGX,      "tilegx"),
        _GPT_ARCH_SEXTET(X86,         "x86"),
        _GPT_ARCH_SEXTET(X86_64,      "x86-64"),
#ifdef GPT_ROOT_NATIVE
        { GPT_ROOT_NATIVE,            "root",            native_architecture() },
        { GPT_ROOT_NATIVE_VERITY,     "root-verity",     native_architecture() },
        { GPT_ROOT_NATIVE_VERITY_SIG, "root-verity-sig", native_architecture() },
        { GPT_USR_NATIVE,             "usr",             native_architecture() },
        { GPT_USR_NATIVE_VERITY,      "usr-verity",      native_architecture() },
        { GPT_USR_NATIVE_VERITY_SIG,  "usr-verity-sig",  native_architecture() },
#endif
#ifdef GPT_ROOT_SECONDARY
        _GPT_ARCH_SEXTET(SECONDARY,   "secondary"),
#endif

        { GPT_ESP,                    "esp",           _ARCHITECTURE_INVALID },
        { GPT_XBOOTLDR,               "xbootldr",      _ARCHITECTURE_INVALID },
        { GPT_SWAP,                   "swap",          _ARCHITECTURE_INVALID },
        { GPT_HOME,                   "home",          _ARCHITECTURE_INVALID },
        { GPT_SRV,                    "srv",           _ARCHITECTURE_INVALID },
        { GPT_VAR,                    "var",           _ARCHITECTURE_INVALID },
        { GPT_TMP,                    "tmp",           _ARCHITECTURE_INVALID },
        { GPT_USER_HOME,              "user-home",     _ARCHITECTURE_INVALID },
        { GPT_LINUX_GENERIC,          "linux-generic", _ARCHITECTURE_INVALID },
        {}
};

#define _GPT_ALL_ARCHES(type,suffix)                    \
        GPT_##type##_ALPHA##suffix,                     \
        GPT_##type##_ARC##suffix,                       \
        GPT_##type##_ARM##suffix,                       \
        GPT_##type##_ARM64##suffix,                     \
        GPT_##type##_IA64##suffix,                      \
        GPT_##type##_LOONGARCH64##suffix,               \
        GPT_##type##_MIPS_LE##suffix,                   \
        GPT_##type##_MIPS64_LE##suffix,                 \
        GPT_##type##_PPC##suffix,                       \
        GPT_##type##_PPC64##suffix,                     \
        GPT_##type##_PPC64_LE##suffix,                  \
        GPT_##type##_RISCV32##suffix,                   \
        GPT_##type##_RISCV64##suffix,                   \
        GPT_##type##_S390##suffix,                      \
        GPT_##type##_S390X##suffix,                     \
        GPT_##type##_TILEGX##suffix,                    \
        GPT_##type##_X86##suffix,                       \
        GPT_##type##_X86_64##suffix

const char *gpt_partition_type_uuid_to_string(sd_id128_t id) {
        for (size_t i = 0; i < ELEMENTSOF(gpt_partition_type_table) - 1; i++)
                if (sd_id128_equal(id, gpt_partition_type_table[i].uuid))
                        return gpt_partition_type_table[i].name;

        return NULL;
}

const char *gpt_partition_type_uuid_to_string_harder(
                sd_id128_t id,
                char buffer[static ID128_UUID_STRING_MAX]) {

        const char *s;

        assert(buffer);

        s = gpt_partition_type_uuid_to_string(id);
        if (s)
                return s;

        return id128_to_uuid_string(id, buffer);
}

int gpt_partition_type_uuid_from_string(const char *s, sd_id128_t *ret) {
        assert(s);

        for (size_t i = 0; i < ELEMENTSOF(gpt_partition_type_table) - 1; i++)
                if (streq(s, gpt_partition_type_table[i].name)) {
                        if (ret)
                                *ret = gpt_partition_type_table[i].uuid;
                        return 0;
                }

        return sd_id128_from_string(s, ret);
}

Architecture gpt_partition_type_uuid_to_arch(sd_id128_t id) {
        for (size_t i = 0; i < ELEMENTSOF(gpt_partition_type_table) - 1; i++)
                if (sd_id128_equal(id, gpt_partition_type_table[i].uuid))
                        return gpt_partition_type_table[i].arch;

        return _ARCHITECTURE_INVALID;
}

int gpt_partition_label_valid(const char *s) {
        _cleanup_free_ char16_t *recoded = NULL;

        recoded = utf8_to_utf16(s, strlen(s));
        if (!recoded)
                return -ENOMEM;

        return char16_strlen(recoded) <= GPT_LABEL_MAX;
}

bool gpt_partition_type_is_root(sd_id128_t id) {
        return sd_id128_in_set(id, _GPT_ALL_ARCHES(ROOT,));
}

bool gpt_partition_type_is_root_verity(sd_id128_t id) {
        return sd_id128_in_set(id, _GPT_ALL_ARCHES(ROOT, _VERITY));
}

bool gpt_partition_type_is_usr(sd_id128_t id) {
        return sd_id128_in_set(id, _GPT_ALL_ARCHES(USR,));
}

bool gpt_partition_type_is_usr_verity(sd_id128_t id) {
        return sd_id128_in_set(id, _GPT_ALL_ARCHES(USR, _VERITY));
}

bool gpt_partition_type_knows_read_only(sd_id128_t id) {
        return gpt_partition_type_is_root(id) ||
                gpt_partition_type_is_usr(id) ||
                sd_id128_in_set(id,
                                GPT_HOME,
                                GPT_SRV,
                                GPT_VAR,
                                GPT_TMP,
                                GPT_XBOOTLDR) ||
                gpt_partition_type_is_root_verity(id) || /* pretty much implied, but let's set the bit to make things really clear */
                gpt_partition_type_is_usr_verity(id);    /* ditto */
}

bool gpt_partition_type_knows_growfs(sd_id128_t id) {
        return gpt_partition_type_is_root(id) ||
                gpt_partition_type_is_usr(id) ||
                sd_id128_in_set(id,
                                GPT_HOME,
                                GPT_SRV,
                                GPT_VAR,
                                GPT_TMP,
                                GPT_XBOOTLDR);
}

bool gpt_partition_type_knows_no_auto(sd_id128_t id) {
        return gpt_partition_type_is_root(id) ||
                gpt_partition_type_is_root_verity(id) ||
                gpt_partition_type_is_usr(id) ||
                gpt_partition_type_is_usr_verity(id) ||
                sd_id128_in_set(id,
                                GPT_HOME,
                                GPT_SRV,
                                GPT_VAR,
                                GPT_TMP,
                                GPT_XBOOTLDR,
                                GPT_SWAP);
}
