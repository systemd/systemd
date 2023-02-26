# SPDX-License-Identifier: LGPL-2.1-or-later

efi_config_h_dir = meson.current_build_dir()

if conf.get('ENABLE_BOOTLOADER') != 1
        subdir_done()
endif

efi_conf = configuration_data()
efi_conf.set10('ENABLE_TPM', get_option('tpm'))

foreach ctype : ['color-normal', 'color-entry', 'color-highlight', 'color-edit']
        c = get_option('efi-' + ctype).split(',')
        efi_conf.set(ctype.underscorify().to_upper(), 'EFI_TEXT_ATTR(@0@, @1@)'.format(
                'EFI_' + c[0].strip().underscorify().to_upper(),
                'EFI_' + c[1].strip().underscorify().to_upper()))
endforeach

if meson.is_cross_build() and get_option('sbat-distro') == 'auto'
        warning('Auto detection of SBAT information not supported when cross-building, disabling SBAT.')
elif get_option('sbat-distro') != ''
        efi_conf.set_quoted('SBAT_PROJECT', meson.project_name())
        efi_conf.set_quoted('PROJECT_VERSION', meson.project_version())
        efi_conf.set('PROJECT_URL', conf.get('PROJECT_URL'))
        if get_option('sbat-distro-generation') < 1
                error('SBAT Distro Generation must be a positive integer')
        endif
        efi_conf.set('SBAT_DISTRO_GENERATION', get_option('sbat-distro-generation'))
        foreach sbatvar : [['sbat-distro', 'ID'],
                           ['sbat-distro-summary', 'NAME'],
                           ['sbat-distro-url', 'BUG_REPORT_URL']]
                value = get_option(sbatvar[0])
                if (value == '' or value == 'auto') and not meson.is_cross_build()
                        cmd = 'if [ -e /etc/os-release ]; then . /etc/os-release; else . /usr/lib/os-release; fi; echo $@0@'.format(sbatvar[1])
                        value = run_command(sh, '-c', cmd, check: true).stdout().strip()
                endif
                if value == ''
                        error('Required @0@ option not set and autodetection failed'.format(sbatvar[0]))
                endif
                efi_conf.set_quoted(sbatvar[0].underscorify().to_upper(), value)
        endforeach

        pkgname = get_option('sbat-distro-pkgname')
        if pkgname == ''
                pkgname = meson.project_name()
        endif
        efi_conf.set_quoted('SBAT_DISTRO_PKGNAME', pkgname)

        pkgver = get_option('sbat-distro-version')
        if pkgver == ''
                efi_conf.set('SBAT_DISTRO_VERSION', 'GIT_VERSION')
                # This is determined during build, not configuration, so we can't display it yet.
                sbat_distro_version_display = '(git version)'
        else
                efi_conf.set_quoted('SBAT_DISTRO_VERSION', pkgver)
                sbat_distro_version_display = pkgver
        endif
endif

summary({'UEFI architecture' : efi_arch},
        section : 'UEFI')

if efi_conf.get('SBAT_DISTRO', '') != ''
        summary({
                'SBAT distro':              efi_conf.get('SBAT_DISTRO'),
                'SBAT distro generation':   efi_conf.get('SBAT_DISTRO_GENERATION'),
                'SBAT distro version':      sbat_distro_version_display,
                'SBAT distro summary':      efi_conf.get('SBAT_DISTRO_SUMMARY'),
                'SBAT distro URL':          efi_conf.get('SBAT_DISTRO_URL')},
                section : 'UEFI')
endif

configure_file(
        output : 'efi_config.h',
        configuration : efi_conf)

############################################################

libefi_sources = files(
        'console.c',
        'device-path-util.c',
        'devicetree.c',
        'drivers.c',
        'efi-string.c',
        'graphics.c',
        'initrd.c',
        'log.c',
        'measure.c',
        'part-discovery.c',
        'pe.c',
        'random-seed.c',
        'secure-boot.c',
        'ticks.c',
        'util.c',
        'vmm.c',
)

systemd_boot_sources = files(
        'boot.c',
        'shim.c',
)

stub_sources = files(
        'cpio.c',
        'linux.c',
        'splash.c',
        'stub.c',
)

if host_machine.cpu_family() in ['x86', 'x86_64']
        stub_sources += files('linux_x86.c')
endif

tests += [
        {
                'sources' : files(
                        'test-efi-string.c',
                        'efi-string.c',
                )
        },
]

# BCD parser only makes sense on arches that Windows supports.
if host_machine.cpu_family() in ['aarch64', 'arm', 'x86_64', 'x86']
        systemd_boot_sources += files('bcd.c')
        tests += [
                {
                        'sources' : files(
                                'test-bcd.c',
                                'efi-string.c',
                        ),
                        'dependencies' : libzstd,
                        'condition' : 'HAVE_ZSTD',
                },
        ]
        fuzzers += [
                {
                        'sources' : files(
                                'fuzz-bcd.c',
                                'bcd.c',
                                'efi-string.c'
                        ),
                },
                {
                        'sources' : files(
                                'fuzz-efi-string.c',
                                'efi-string.c'
                        ),
                },
                {
                        'sources' : files(
                                'fuzz-efi-printf.c',
                                'efi-string.c'
                        ),
                },
        ]
endif
