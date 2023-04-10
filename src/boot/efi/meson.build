# SPDX-License-Identifier: LGPL-2.1-or-later

efi_config_h_dir = meson.current_build_dir()

if efi_arch != ''
        libefitest = static_library(
                'efitest',
                files(
                        'bcd.c',
                        'efi-string.c',
                ),
                build_by_default : false,
                include_directories : [
                        basic_includes,
                        include_directories('.'),
                ],
                dependencies : userspace)

        efitest_base = {
                'link_with' : [
                        libefitest,
                        libshared,
                ],
        }

        tests += [
                {
                        'sources' : files('test-bcd.c'),
                        'dependencies' : libzstd,
                        'condition' : 'HAVE_ZSTD',
                        'base' : efitest_base,
                },
                {
                        'sources' : files('test-efi-string.c'),
                        'base' : efitest_base,
                },
        ]
        fuzzers += [
                {
                        'sources' : files('fuzz-bcd.c'),
                        'base' : efitest_base,
                },
                {
                        'sources' : files('fuzz-efi-string.c'),
                        'base' : efitest_base,
                },
                {
                        'sources' : files('fuzz-efi-printf.c'),
                        'base' : efitest_base,
                },
        ]
endif

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

summary({'UEFI architectures' : efi_arch + (efi_arch_alt == '' ? '' : ', ' + efi_arch_alt)},
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

efi_includes = [fundamental_include, include_directories('.')]

efi_c_args = [
        '-DSD_BOOT=1',
        '-ffreestanding',
        '-fno-strict-aliasing',
        '-fshort-wchar',
        '-include', 'efi_config.h',
]

efi_c_args += cc.get_supported_arguments(
        '-fwide-exec-charset=UCS2',
        # gcc docs says this is required for ms_abi to work correctly.
        '-maccumulate-outgoing-args',
        '-mstack-protector-guard=global',
)

# Debug information has little value in release builds as no normal human being knows
# how to attach a debugger to EFI binaries running on real hardware. Anyone who does
# certainly has the means to do their own dev build.
if get_option('mode') == 'developer' and get_option('debug')
        efi_c_args += '-DEFI_DEBUG'
endif

efi_c_ld_args = [
        # We only support bfd. gold is going away, lld has issues with LTO on x86
        # and mold does not support linker scripts.
        '-fuse-ld=bfd',

        '-lgcc',
        '-nostdlib',
        '-static-pie',
        '-Wl,--entry=efi_main',
        '-Wl,--fatal-warnings',

        # These flags should be passed by -static-pie, but seem to be missing sometimes.
        '-Wl,--no-dynamic-linker',
        '-z', 'text',

        # EFI has 4KiB pages.
        '-z', 'common-page-size=4096',
        '-z', 'max-page-size=4096',

        '-z', 'noexecstack',
        '-z', 'norelro',
        '-T' + elf2efi_lds,
]

# efi_c_args is explicitly passed to targets so that they can override distro-provided flags
# that should not be used for EFI binaries.
efi_disabled_c_args = cc.get_supported_arguments(
        '-fcf-protection=none',
        '-fno-asynchronous-unwind-tables',
        '-fno-exceptions',
        '-fno-unwind-tables',
)
efi_override_options = [
        'b_coverage=false',
        'b_pgo=off',
]

if get_option('b_sanitize') == 'undefined'
        efi_disabled_c_args += cc.get_supported_arguments('-fno-sanitize-link-runtime')
else
        efi_disabled_c_args += cc.get_supported_arguments('-fno-sanitize=all')
        efi_override_options += 'b_sanitize=none'
endif

efi_c_args += efi_disabled_c_args
efi_c_ld_args += efi_disabled_c_args

if cc.get_id() == 'clang'
        # clang is too picky sometimes.
        efi_c_args += '-Wno-unused-command-line-argument'
        efi_c_ld_args += '-Wno-unused-command-line-argument'
endif

if host_machine.cpu_family() == 'arm'
        # libgcc is not compiled with -fshort-wchar, but it does not use it anyways,
        # so it's fine to link against it.
        efi_c_ld_args += '-Wl,--no-wchar-size-warning'
endif

efi_c_args_primary = [efi_c_args, '-DEFI_MACHINE_TYPE_NAME="' + efi_arch + '"']
efi_c_args_alt = [efi_c_args, '-DEFI_MACHINE_TYPE_NAME="' + efi_arch_alt + '"']
efi_c_ld_args_primary = efi_c_ld_args
efi_c_ld_args_alt = efi_c_ld_args

efi_arch_c_args = {
        'aarch64' : ['-mgeneral-regs-only'],
        'arm'     : ['-mgeneral-regs-only'],
        'x86_64'  : ['-march=x86-64', '-mno-red-zone', '-mgeneral-regs-only'],
        'x86'     : ['-march=i686', '-mgeneral-regs-only', '-malign-double'],
}
efi_c_args_primary += efi_arch_c_args.get(host_machine.cpu_family(), [])

if efi_arch_alt == 'ia32'
        efi_c_args_alt += ['-m32', efi_arch_c_args['x86']]
        efi_c_ld_args_alt += '-m32'
endif

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

if get_option('b_sanitize') == 'undefined'
        libefi_sources += files('ubsan.c')
endif

if host_machine.cpu_family() in ['x86', 'x86_64']
        stub_sources += files('linux_x86.c')
endif

# BCD parser only makes sense on arches that Windows supports.
if host_machine.cpu_family() in ['aarch64', 'arm', 'x86_64', 'x86']
        systemd_boot_sources += files('bcd.c')
endif

boot_targets = []
efi_elf_binaries = []
efi_archspecs = [
        {
                'arch' : efi_arch,
                'c_args' : efi_c_args_primary,
                'link_args' : efi_c_ld_args_primary,
        },
]
if efi_arch_alt != ''
        efi_archspecs += {
                'arch' : efi_arch_alt,
                'c_args' : efi_c_args_alt,
                'link_args' : efi_c_ld_args_alt,
        }
endif

foreach archspec : efi_archspecs
        libefi = static_library(
                'efi' + archspec['arch'],
                fundamental_sources,
                libefi_sources,
                include_directories : efi_includes,
                c_args : archspec['c_args'],
                dependencies : versiondep,
                gnu_symbol_visibility : 'hidden',
                override_options : efi_override_options,
                pic : true)

        efi_elf_binaries += executable(
                'systemd-boot' + archspec['arch'],
                systemd_boot_sources,
                include_directories : efi_includes,
                c_args : archspec['c_args'],
                link_args : archspec['link_args'],
                link_with : libefi,
                link_depends : elf2efi_lds,
                dependencies : versiondep,
                gnu_symbol_visibility : 'hidden',
                override_options : efi_override_options,
                name_suffix : 'elf',
                pie : true)

        efi_elf_binaries += executable(
                'linux' + archspec['arch'],
                stub_sources,
                include_directories : efi_includes,
                c_args : archspec['c_args'],
                link_args : archspec['link_args'],
                link_with : libefi,
                link_depends : elf2efi_lds,
                dependencies : versiondep,
                gnu_symbol_visibility : 'hidden',
                override_options : efi_override_options,
                name_suffix : 'elf.stub',
                pie : true)
endforeach

foreach efi_elf_binary : efi_elf_binaries
        # FIXME: Use build_tgt.name() with meson >= 0.54.0
        name = fs.name(efi_elf_binary.full_path()).split('.')[0]
        name += name.startswith('linux') ? '.efi.stub' : '.efi'
        boot_targets += custom_target(
                name,
                output : name,
                input : efi_elf_binary,
                install : true,
                install_dir : bootlibdir,
                install_tag : 'systemd-boot',
                command : [
                        elf2efi_py,
                        '--version-major=' + meson.project_version(),
                        '--version-minor=0',
                        '--efi-major=1',
                        '--efi-minor=1',
                        '--subsystem=10',
                        '@INPUT@',
                        '@OUTPUT@',
                ])
endforeach

alias_target('systemd-boot', boot_targets)
