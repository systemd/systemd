# SPDX-License-Identifier: LGPL-2.1-or-later

efi_config_h_dir = meson.current_build_dir()
efi_addon = ''

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
efi_test_template = test_template + efitest_base
efi_fuzz_template = fuzz_template + efitest_base

executables += [
        efi_test_template + {
                'sources' : files('test-bcd.c'),
                'dependencies' : libzstd,
                'conditions' : ['ENABLE_BOOTLOADER', 'HAVE_ZSTD'],
        },
        efi_test_template + {
                'sources' : files('test-efi-string.c'),
                'conditions' : ['ENABLE_BOOTLOADER'],
        },
        efi_fuzz_template + {
                'sources' : files('fuzz-bcd.c'),
        },
        efi_fuzz_template + {
                'sources' : files('fuzz-efi-string.c'),
        },
        efi_fuzz_template + {
                'sources' : files('fuzz-efi-osrel.c'),
        },
        efi_fuzz_template + {
                'sources' : files('fuzz-efi-printf.c'),
        },
]

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
                # This is determined during build, not configuration, so we can't display it yet.
                efi_conf.set('SBAT_DISTRO_VERSION', 'GIT_VERSION')
        else
                efi_conf.set_quoted('SBAT_DISTRO_VERSION', pkgver)
        endif
endif

summary({'UEFI architectures' : efi_arch + (efi_arch_alt == '' ? '' : ', ' + efi_arch_alt)},
        section : 'UEFI')

if efi_conf.get('SBAT_DISTRO', '') != ''
        summary({
                'SBAT distro':              efi_conf.get('SBAT_DISTRO'),
                'SBAT distro generation':   efi_conf.get('SBAT_DISTRO_GENERATION'),
                'SBAT distro version':      efi_conf.get('SBAT_DISTRO_VERSION'),
                'SBAT distro summary':      efi_conf.get('SBAT_DISTRO_SUMMARY'),
                'SBAT distro URL':          efi_conf.get('SBAT_DISTRO_URL')},
                section : 'UEFI')
endif

configure_file(
        output : 'efi_config.h',
        configuration : efi_conf)

############################################################

efi_includes = [
        build_dir_include,
        fundamental_include,
        include_directories('.'),
]

efi_c_args = [
        '-DSD_BOOT=1',
        '-ffreestanding',
        '-fstrict-aliasing',
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
        '-lgcc',
        '-nostdlib',
        '-static-pie',
        '-Wl,--entry=efi_main',
        '-Wl,--fatal-warnings',

        # These flags should be passed by -static-pie, but for whatever reason the flag translation
        # is not enabled on all architectures. Not passing `-static` would just allow the linker to
        # use dynamic libraries, (which we can't/don't use anyway). But if `-pie` is missing and the
        # gcc build does not default to `-pie` we get a regular (no-pie) binary that will be
        # rightfully rejected by elf2efi. Note that meson also passes `-pie` to the linker driver,
        # but it is overridden by our `-static-pie`. We also need to pass these directly to the
        # linker as `-static`+`-pie` seem to get translated differently.
        '-Wl,-static,-pie,--no-dynamic-linker,-z,text',

        # EFI has 4KiB pages.
        '-z', 'common-page-size=4096',
        '-z', 'max-page-size=4096',

        '-z', 'noexecstack',
        '-z', 'relro',
        '-z', 'separate-code',
]

efi_c_ld_args += cc.get_supported_link_arguments(
        # binutils >= 2.38
        '-Wl,-z,nopack-relative-relocs',
)

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

efi_arch_c_args = {
        'aarch64' : ['-mgeneral-regs-only'],
        'arm'     : ['-mgeneral-regs-only'],
        # Pass -m64/32 explicitly to make building on x32 work.
        'x86_64'  : ['-m64', '-march=x86-64', '-mno-red-zone', '-mgeneral-regs-only'],
        'x86'     : ['-m32', '-march=i686', '-mgeneral-regs-only', '-malign-double'],
}
efi_arch_c_ld_args = {
        # libgcc is not compiled with -fshort-wchar, but it does not use it anyways,
        # so it's fine to link against it.
        'arm'    : cc.get_supported_link_arguments('-Wl,--no-wchar-size-warning'),
        'x86_64' : ['-m64'],
        'x86'    : ['-m32'],
}

linker_sanity_code = 'void a(void) {}; void _start(void) { a(); }'
linker_sanity_args = ['-nostdlib', '-Wl,--fatal-warnings']
if not cc.links(linker_sanity_code,
                name : 'linker supports -static-pie',
                args : [linker_sanity_args, '-static-pie'])
        error('Linker does not support -static-pie.')
endif

# https://github.com/llvm/llvm-project/issues/67152
if not cc.links(linker_sanity_code,
                name : 'linker supports LTO with -nostdlib',
                args : [linker_sanity_args, '-flto'])
        efi_c_args += '-fno-lto'
        efi_c_ld_args += '-fno-lto'
endif

# https://github.com/llvm/llvm-project/issues/61101
if efi_cpu_family_alt == 'x86' and not cc.links(linker_sanity_code,
                name : 'linker supports LTO with -nostdlib (x86)',
                args : [linker_sanity_args, '-flto', '-m32'])
        efi_arch_c_args += { 'x86' : efi_arch_c_args['x86'] + '-fno-lto' }
        efi_arch_c_ld_args += { 'x86' : efi_arch_c_ld_args['x86'] + '-fno-lto' }
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
        'shim.c',
        'ticks.c',
        'util.c',
        'vmm.c',
)

systemd_boot_sources = files(
        'boot.c',
)

stub_sources = files(
        'cpio.c',
        'linux.c',
        'splash.c',
        'stub.c',
)

addon_sources = files(
        'addon.c',
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
                'c_args' : [
                        efi_c_args,
                        '-DEFI_MACHINE_TYPE_NAME="' + efi_arch + '"',
                        efi_arch_c_args.get(host_machine.cpu_family(), []),
                ],
                'link_args' : [
                        efi_c_ld_args,
                        efi_arch_c_ld_args.get(host_machine.cpu_family(), []),
                ],
        },
]
if efi_arch_alt != ''
        efi_archspecs += {
                'arch' : efi_arch_alt,
                'c_args' : [
                        efi_c_args,
                        '-DEFI_MACHINE_TYPE_NAME="' + efi_arch_alt + '"',
                        efi_arch_c_args.get(efi_cpu_family_alt, []),
                ],
                'link_args' : [
                        efi_c_ld_args,
                        efi_arch_c_ld_args.get(efi_cpu_family_alt, []),
                ],
        }
endif

foreach archspec : efi_archspecs
        libefi = static_library(
                'efi' + archspec['arch'],
                fundamental_sources,
                libefi_sources,
                version_h,
                include_directories : efi_includes,
                c_args : archspec['c_args'],
                gnu_symbol_visibility : 'hidden',
                override_options : efi_override_options,
                pic : true)

        kwargs = {
                'include_directories' : efi_includes,
                'c_args' : archspec['c_args'],
                'link_args' : archspec['link_args'],
                'gnu_symbol_visibility' : 'hidden',
                'override_options' : efi_override_options,
                'pie' : true,
        }

        efi_elf_binaries += executable(
                'systemd-boot' + archspec['arch'],
                sources : [systemd_boot_sources, version_h],
                link_with : libefi,
                name_suffix : 'elf',
                kwargs : kwargs)

        efi_elf_binaries += executable(
                'linux' + archspec['arch'],
                sources : [stub_sources, version_h],
                link_with : libefi,
                name_suffix : 'elf.stub',
                kwargs : kwargs)

        efi_elf_binaries += executable(
                'addon' + archspec['arch'],
                sources : [addon_sources, version_h],
                name_suffix : 'elf.stub',
                kwargs : kwargs)
endforeach

foreach efi_elf_binary : efi_elf_binaries
        name = efi_elf_binary.name()
        name += name.startswith('systemd-boot') ? '.efi' : '.efi.stub'
        # For the addon, given it's empty, we need to explicitly reserve space in the header to account for
        # the sections that ukify will add.
        minimum_sections = name.endswith('.stub') ? '15' : '0'
        exe = custom_target(
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
                        '--minimum-sections=' + minimum_sections,
                        '--copy-sections=.sbat,.sdmagic,.osrel',
                        '@INPUT@',
                        '@OUTPUT@',
                ])
        boot_targets += exe
        if name.startswith('linux')
                boot_stubs += exe
        endif

        # This is supposed to match exactly one time
        if name == 'addon@0@.efi.stub'.format(efi_arch)
                efi_addon = exe.full_path()
        endif
endforeach

alias_target('systemd-boot', boot_targets)
