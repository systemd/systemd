# SPDX-License-Identifier: LGPL-2.1-or-later

bootctl_sources = files(
        'bootctl-install.c',
        'bootctl-install.h',
        'bootctl-random-seed.c',
        'bootctl-random-seed.h',
        'bootctl-reboot-to-firmware.c',
        'bootctl-reboot-to-firmware.h',
        'bootctl-set-efivar.c',
        'bootctl-set-efivar.h',
        'bootctl-status.c',
        'bootctl-status.h',
        'bootctl-systemd-efi-options.c',
        'bootctl-systemd-efi-options.h',
        'bootctl-util.c',
        'bootctl-util.h',
        'bootctl.c',
        'bootctl.h',
)

if conf.get('ENABLE_BOOTCTL') == 1 and efi_arch != ''
        libefitest_sources = files(
                'efi/bcd.c',
                'efi/bcd.h',
                'efi/efi-string.c',
                'efi/efi-string.h',
        )
        libefitest = static_library(
                'efitest',
                libefitest_sources,
                include_directories : includes,
                link_with : libshared,
                build_by_default : false)

        tests += [
                [files('efi/test-bcd.c'), [libefitest], [libzstd], [], 'HAVE_ZSTD'],
                [files('efi/test-efi-string.c'), [libefitest]],
        ]
        fuzzers += [
                [files('efi/fuzz-bcd.c'), [libefitest]],
                [files('efi/fuzz-efi-string.c'), [libefitest]],
                [files('efi/fuzz-efi-printf.c'), [libefitest]],
        ]
endif
