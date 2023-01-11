# SPDX-License-Identifier: LGPL-2.1-or-later

# EFI binaries are just plain static PE/COFF binaries. To bulid them natively with meson we have to
# be cross-building for windows. The cross-*.ini files provide suitable defaults to pass via --cross-file=
# to meson. Since there is no windows port of systemd (yet), we will short-circuit the rest of the
# root meson.build file after returning from here.
conf.set10('SD_BOOT', meson.is_cross_build() and host_machine.system() == 'windows')

efi_arch = {
        'aarch64' : 'aa64',
        'arm'     : 'arm',
        'x86_64'  : 'x64',
        'x86'     : 'ia32',
}.get(host_machine.cpu_family(), '')
if efi_arch != ''
        conf.set_quoted('EFI_MACHINE_TYPE_NAME', efi_arch)
        summary({'EFI arch' : efi_arch})
elif conf.get('SD_BOOT') == 1
        error('Unsupported EFI architecture: @0@'.format(host_machine.cpu_family()))
endif

if conf.get('SD_BOOT') == 0 and meson.is_cross_build() and get_option('sbat-distro') == 'auto'
        warning('Auto detection of SBAT information not supported when cross-building, disabling SBAT.')
elif get_option('sbat-distro') != ''
        conf.set_quoted('SBAT_PROJECT', meson.project_name())

        if get_option('sbat-distro-generation') < 1
                error('SBAT Distro Generation must be a positive integer')
        endif
        conf.set('SBAT_DISTRO_GENERATION', get_option('sbat-distro-generation'))

        foreach sbatvar : [['sbat-distro', 'ID'],
                           ['sbat-distro-summary', 'NAME'],
                           ['sbat-distro-url', 'BUG_REPORT_URL']]
                value = get_option(sbatvar[0])
                if (value == '' or value == 'auto') and (conf.get('SD_BOOT') == 1 or not meson.is_cross_build())
                        cmd = 'if [ -e /etc/os-release ]; then . /etc/os-release; else . /usr/lib/os-release; fi; echo $@0@'.format(sbatvar[1])
                        value = run_command('sh', '-c', cmd, check: true).stdout().strip()
                endif
                if value == ''
                        error('Required @0@ option not set and autodetection failed'.format(sbatvar[0]))
                endif
                conf.set_quoted(sbatvar[0].underscorify().to_upper(), value)
        endforeach

        pkgname = get_option('sbat-distro-pkgname')
        if pkgname == ''
                pkgname = meson.project_name()
        endif
        conf.set_quoted('SBAT_DISTRO_PKGNAME', pkgname)

        pkgver = get_option('sbat-distro-version')
        if pkgver == ''
                conf.set('SBAT_DISTRO_VERSION', 'GIT_VERSION')
                # This is determined during build, not configuration, so we can't display it yet.
                sbat_distro_version_display = '(git version)'
        else
                conf.set_quoted('SBAT_DISTRO_VERSION', pkgver)
                sbat_distro_version_display = pkgver
        endif

        if conf.get('SBAT_DISTRO', '') != ''
                summary({
                        'SBAT distro':              conf.get('SBAT_DISTRO'),
                        'SBAT distro generation':   conf.get('SBAT_DISTRO_GENERATION'),
                        'SBAT distro version':      sbat_distro_version_display,
                        'SBAT distro summary':      conf.get('SBAT_DISTRO_SUMMARY'),
                        'SBAT distro URL':          conf.get('SBAT_DISTRO_URL')},
                        section : 'UEFI Secure Boot Advanced Targeting (SBAT)')
        endif
endif

# Userspace build?
if conf.get('SD_BOOT') != 1
        subdir_done()
endif

############################################################

# When compiling for Windows targets with clang there are two target flavors: *-windows and *-windows-gnu.
# The former behaves very close to MSVC and is unfavorable for our GNU based sources. It also makes clang
# emit intrinsics that use Microsoft names, which are neither provided by compiler-rt or libgcc. The -gnu
# flavor will make clang behave like gcc (mingw) again and emits the right intrinsics. gcc for PE/Windows
# targets will always be mingw and provide this define.
if cc.get_define('__MINGW32__') != '1'
        error('Must use mingw compiler or use -gnu flavor target triple!')
endif

conf.set10('ENABLE_TPM', get_option('tpm'))

foreach ctype : ['color-normal', 'color-entry', 'color-highlight', 'color-edit']
        c = get_option('efi-' + ctype).split(',')
        conf.set(ctype.underscorify().to_upper(), 'EFI_TEXT_ATTR(@0@, @1@)'.format(
                'EFI_' + c[0].strip().underscorify().to_upper(),
                'EFI_' + c[1].strip().underscorify().to_upper()))
endforeach

config_h = configure_file(
        output : 'config.h',
        configuration : conf)

############################################################

efi_includes = [fundamental_include, include_directories('.')]

efi_c_args = [
        '-ffreestanding',
        '-fno-stack-protector',
        '-fno-strict-aliasing',
] + {
        'aarch64': ['-mgeneral-regs-only'],
        'arm':     ['-mfpu=none'],
        'x86_64':  ['-mno-red-zone', '-mno-sse', '-mno-mmx'],
        'x86':     ['-mno-sse', '-mno-mmx'],
}.get(host_machine.cpu_family())

boot_c_args = [
        '-include', 'config.h',
] + cc.get_supported_arguments(
        basic_disabled_warnings,
        possible_common_cc_flags,
        '-fwide-exec-charset=UCS2',
)

# Really only for i386.
entry_prefix = cc.symbols_have_underscore_prefix() ? '_' : ''

efi_c_ld_args = [
        '-nostdlib',
        '-static',
        '-Wl,--entry=' + entry_prefix + 'efi_main',
        '-lgcc',
]

############################################################

libefi_sources = files(
        'console.c',
        'console.h',
        'device-path-util.c',
        'device-path-util.h',
        'devicetree.c',
        'devicetree.h',
        'drivers.c',
        'drivers.h',
        'efi-string.c',
        'efi-string.h',
        'efi.h',
        'graphics.c',
        'graphics.h',
        'initrd.c',
        'initrd.h',
        'log.c',
        'log.h',
        'measure.c',
        'measure.h',
        'part-discovery.c',
        'part-discovery.h',
        'pe.c',
        'pe.h',
        'proto-block-io.h',
        'proto-console-control.h',
        'proto-device-path.h',
        'proto-dt-fixup.h',
        'proto-file-io.h',
        'proto-graphics-output.h',
        'proto-load-file.h',
        'proto-loaded-image.h',
        'proto-rng.h',
        'proto-security-arch.h',
        'proto-shell-parameters.h',
        'proto-simple-text-io.h',
        'proto-tcg.h',
        'random-seed.c',
        'random-seed.h',
        'secure-boot.c',
        'secure-boot.h',
        'ticks.c',
        'ticks.h',
        'util.c',
        'util.h',
        'vmm.c',
        'vmm.h',
)

systemd_boot_sources = files(
        'bcd.c',
        'bcd.h',
        'boot.c',
        'shim.c',
        'shim.h',
)

stub_sources = files(
        'cpio.c',
        'cpio.h',
        'linux.c',
        'linux.h',
        'splash.c',
        'splash.h',
        'stub.c',
)

if host_machine.cpu_family() in ['x86', 'x86_64']
        stub_sources += files('linux_x86.c')
endif

############################################################

add_project_arguments(efi_c_args, language : 'c')
add_project_link_arguments(efi_c_ld_args, language : 'c')

libefi = static_library(
        'efi',
        [fundamental_sources, libefi_sources],
        c_args : boot_c_args,
        include_directories : efi_includes,
        dependencies : [versiondep])
