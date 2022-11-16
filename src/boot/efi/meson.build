# SPDX-License-Identifier: LGPL-2.1-or-later

conf.set10('ENABLE_EFI', get_option('efi'))
conf.set10('HAVE_GNU_EFI', false)

efi_config_h_dir = meson.current_build_dir()

if not get_option('efi') or get_option('gnu-efi') == 'false'
        if get_option('gnu-efi') == 'true'
                error('gnu-efi support requested, but general efi support is disabled')
        endif
        subdir_done()
endif

efi_arch = host_machine.cpu_family()
if efi_arch == 'x86' and '-m64' in get_option('efi-cflags')
        efi_arch = 'x86_64'
elif efi_arch == 'x86_64' and '-m32' in get_option('efi-cflags')
        efi_arch = 'x86'
endif
efi_arch = {
        # host_cc_arch: [efi_arch (see Table 3-2 in UEFI spec), gnu_efi_inc_arch]
        'x86':     ['ia32', 'ia32'],
        'x86_64':  ['x64', 'x86_64'],
        'arm':     ['arm', 'arm'],
        'aarch64': ['aa64', 'aarch64'],
        'riscv64': ['riscv64', 'riscv64'],
}.get(efi_arch, [])

efi_incdir = get_option('efi-includedir')
if efi_arch.length() > 0 and not cc.has_header(
                '@0@/@1@/efibind.h'.format(efi_incdir, efi_arch[1]),
                args: get_option('efi-cflags'))

        efi_arch = []
endif

if efi_arch.length() == 0
        if get_option('gnu-efi') == 'true'
                error('gnu-efi support requested, but headers not found or efi arch is unknown')
        endif
        warning('gnu-efi headers not found or efi arch is unknown, disabling gnu-efi support')
        subdir_done()
endif

if not cc.has_header_symbol('efi.h', 'EFI_IMAGE_MACHINE_X64',
                args: ['-nostdlib', '-ffreestanding', '-fshort-wchar'] + get_option('efi-cflags'),
                include_directories: include_directories(efi_incdir, efi_incdir / efi_arch[1]))

        if get_option('gnu-efi') == 'true'
                error('gnu-efi support requested, but found headers are too old (3.0.5+ required)')
        endif
        warning('gnu-efi headers are too old (3.0.5+ required), disabling gnu-efi support')
        subdir_done()
endif

objcopy = run_command(cc.cmd_array(), '-print-prog-name=objcopy', check: true).stdout().strip()

efi_ld = get_option('efi-ld')
if efi_ld == 'auto'
        efi_ld = cc.get_linker_id().split('.')[1]
        if efi_ld not in ['bfd', 'gold']
                message('Not using @0@ as efi-ld, falling back to bfd'.format(efi_ld))
                efi_ld = 'bfd'
        endif
endif

efi_multilib = run_command(
        cc.cmd_array(), '-print-multi-os-directory', get_option('efi-cflags'),
        check: false
).stdout().strip()
efi_multilib = run_command(
        'realpath', '-e', '/usr/lib' / efi_multilib,
        check: false
).stdout().strip()

efi_libdir = ''
foreach dir : [get_option('efi-libdir'),
               '/usr/lib/gnuefi' / efi_arch[0],
               efi_multilib]
        if dir != '' and fs.is_dir(dir)
                efi_libdir = dir
                break
        endif
endforeach
if efi_libdir == ''
        if get_option('gnu-efi') == 'true'
                error('gnu-efi support requested, but efi-libdir was not found')
        endif
        warning('efi-libdir was not found, disabling gnu-efi support')
        subdir_done()
endif

efi_lds = ''
foreach location : [ # New locations first introduced with gnu-efi 3.0.11
                    [efi_libdir / 'efi.lds',
                     efi_libdir / 'crt0.o'],
                    # Older locations...
                    [efi_libdir / 'gnuefi' / 'elf_@0@_efi.lds'.format(efi_arch[1]),
                     efi_libdir / 'gnuefi' / 'crt0-efi-@0@.o'.format(efi_arch[1])],
                    [efi_libdir / 'elf_@0@_efi.lds'.format(efi_arch[1]),
                     efi_libdir / 'crt0-efi-@0@.o'.format(efi_arch[1])]]
        if fs.is_file(location[0]) and fs.is_file(location[1])
                efi_lds = location[0]
                efi_crt0 = location[1]
                break
        endif
endforeach
if efi_lds == ''
        if get_option('gnu-efi') == 'true'
                error('gnu-efi support requested, but cannot find efi.lds')
        endif
        warning('efi.lds was not found, disabling gnu-efi support')
        subdir_done()
endif

conf.set10('HAVE_GNU_EFI', true)
conf.set_quoted('EFI_MACHINE_TYPE_NAME', efi_arch[0])

efi_conf = configuration_data()
efi_conf.set_quoted('EFI_MACHINE_TYPE_NAME', efi_arch[0])
efi_conf.set10('ENABLE_TPM', get_option('tpm'))
efi_conf.set10('EFI_TPM_PCR_COMPAT', get_option('efi-tpm-pcr-compat'))

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

efi_config_h = configure_file(
        output : 'efi_config.h',
        configuration : efi_conf)

efi_cflags = [
        '-DGNU_EFI_USE_MS_ABI',
        '-DSD_BOOT',
        '-ffreestanding',
        '-fshort-wchar',
        '-fvisibility=hidden',
        '-I', fundamental_path,
        '-I', meson.current_source_dir(),
        '-include', efi_config_h,
        '-include', version_h,
        '-isystem', efi_incdir / efi_arch[1],
        '-isystem', efi_incdir,
        '-std=gnu11',
        '-Wall',
        '-Wextra',
] + cc.get_supported_arguments(
        basic_disabled_warnings +
        possible_common_cc_flags + [
                '-fno-stack-protector',
                '-fno-strict-aliasing',
                '-fpic',
                '-fwide-exec-charset=UCS2',
        ]
)

# Our code size has increased enough to possibly create overlapping PE sections
# at sd-stub runtime, which will often enough prevent the image from booting.
# This only happens because the usual instructions for assembling a unified
# kernel image contain hardcoded addresses for section VMAs added in. Until a
# proper solution is in place, we can at least compile with as least -O1 to
# reduce the likelihood of this happening.
# https://github.com/systemd/systemd/issues/24202
efi_cflags += '-O1'

efi_cflags += cc.get_supported_arguments({
        'ia32':   ['-mno-sse', '-mno-mmx'],
        'x86_64': ['-mno-red-zone', '-mno-sse', '-mno-mmx'],
        'arm':    ['-mgeneral-regs-only', '-mfpu=none'],
}.get(efi_arch[1], []))

# We are putting the efi_cc command line together ourselves, so make sure to pull any
# relevant compiler flags from meson/CFLAGS as povided by the user or distro.

if get_option('werror')
        efi_cflags += ['-Werror']
endif
if get_option('debug') and get_option('mode') == 'developer'
        efi_cflags += ['-ggdb', '-DEFI_DEBUG']
endif
if get_option('optimization') in ['1', '2', '3', 's', 'g']
        efi_cflags += ['-O' + get_option('optimization')]
endif
if get_option('b_ndebug') == 'true' or (
   get_option('b_ndebug') == 'if-release' and get_option('buildtype') in ['plain', 'release'])
        efi_cflags += ['-DNDEBUG']
endif
if get_option('b_lto')
        efi_cflags += cc.has_argument('-flto=auto') ? ['-flto=auto'] : ['-flto']
endif

foreach arg : get_option('c_args')
        if arg in [
                '-DNDEBUG',
                '-fno-lto',
                '-O1', '-O2', '-O3', '-Og', '-Os',
                '-Werror',
           ] or arg.split('=')[0] in [
                '-ffile-prefix-map',
                '-flto',
           ] or (get_option('mode') == 'developer' and arg in [
                '-DEFI_DEBUG',
                '-g', '-ggdb',
           ])

                message('Using "@0@" from c_args for EFI compiler'.format(arg))
                efi_cflags += arg
        endif
endforeach

efi_cflags += get_option('efi-cflags')

efi_ldflags = [
        '-fuse-ld=' + efi_ld,
        '-L', efi_libdir,
        '-nostdlib',
        '-T', efi_lds,
        '-Wl,--build-id=sha1',
        '-Wl,--fatal-warnings',
        '-Wl,--no-undefined',
        '-Wl,--warn-common',
        '-Wl,-Bsymbolic',
        '-z', 'nocombreloc',
        efi_crt0,
]

foreach arg : ['-Wl,--no-warn-execstack',
               '-Wl,--no-warn-rwx-segments']
        # We need to check the correct linker for supported args. This is what
        # cc.has_multi_link_arguments() is for, but it helpfully overrides our
        # choice of linker by putting its own -fuse-ld= arg after ours.
        if run_command('bash', '-c',
                       'exec "$@" -x c -o/dev/null <(echo "int main(void){return 0;}")' +
                       ' -fuse-ld=' + efi_ld + ' -Wl,--fatal-warnings ' + arg,
                       'bash', cc.cmd_array(),
                       check : false).returncode() == 0
                efi_ldflags += arg
        endif
endforeach

if efi_arch[1] in ['aarch64', 'arm', 'riscv64']
        efi_ldflags += ['-shared']
        # Aarch64, ARM32 and 64bit RISC-V don't have an EFI capable objcopy.
        # Use 'binary' instead, and add required symbols manually.
        efi_ldflags += ['-Wl,--defsym=EFI_SUBSYSTEM=0xa']
        efi_format = ['-O', 'binary']
else
        efi_ldflags += ['-pie']
        if efi_ld == 'bfd'
                efi_ldflags += '-Wl,--no-dynamic-linker'
        endif
        efi_format = ['--target=efi-app-@0@'.format(efi_arch[1])]
endif

if efi_arch[1] == 'arm'
        # On arm, the compiler (correctly) warns about wchar_t size mismatch. This
        # is because libgcc is not compiled with -fshort-wchar, but it does not
        # have any occurrences of wchar_t in its sources or the documentation, so
        # it is safe to assume that we can ignore this warning.
        efi_ldflags += ['-Wl,--no-wchar-size-warning']
endif

if run_command('grep', '-q', '__CTOR_LIST__', efi_lds, check: false).returncode() == 0
        # fedora has a patched gnu-efi that adds support for ELF constructors.
        # If ld is called by gcc something about these symbols breaks, resulting
        # in sd-boot freezing when gnu-efi runs the constructors. Force defining
        # them seems to work around this.
        efi_ldflags += [
                '-Wl,--defsym=_init_array=0',
                '-Wl,--defsym=_init_array_end=0',
                '-Wl,--defsym=_fini_array=0',
                '-Wl,--defsym=_fini_array_end=0',
                '-Wl,--defsym=__CTOR_LIST__=0',
                '-Wl,--defsym=__CTOR_END__=0',
                '-Wl,--defsym=__DTOR_LIST__=0',
                '-Wl,--defsym=__DTOR_END__=0',
        ]
endif

if cc.get_id() == 'clang' and cc.version().split('.')[0].to_int() <= 10
        # clang <= 10 doesn't pass -T to the linker and then even complains about it being unused
        efi_ldflags += ['-Wl,-T,' + efi_lds, '-Wno-unused-command-line-argument']
endif

summary({
        'EFI machine type' :                efi_arch[0],
        'EFI LD' :                          efi_ld,
        'EFI lds' :                         efi_lds,
        'EFI crt0' :                        efi_crt0,
        'EFI include directory' :           efi_incdir},
        section : 'Extensible Firmware Interface')

if efi_conf.get('SBAT_DISTRO', '') != ''
        summary({
                'SBAT distro':              efi_conf.get('SBAT_DISTRO'),
                'SBAT distro generation':   efi_conf.get('SBAT_DISTRO_GENERATION'),
                'SBAT distro version':      sbat_distro_version_display,
                'SBAT distro summary':      efi_conf.get('SBAT_DISTRO_SUMMARY'),
                'SBAT distro URL':          efi_conf.get('SBAT_DISTRO_URL')},
                section : 'Extensible Firmware Interface')
endif

############################################################

efi_headers = files(
        'bcd.h',
        'console.h',
        'cpio.h',
        'devicetree.h',
        'disk.h',
        'drivers.h',
        'efi-string.h',
        'graphics.h',
        'initrd.h',
        'linux.h',
        'measure.h',
        'missing_efi.h',
        'pe.h',
        'random-seed.h',
        'secure-boot.h',
        'shim.h',
        'splash.h',
        'ticks.h',
        'util.h',
        'xbootldr.h',
)

common_sources = files(
        'assert.c',
        'console.c',
        'devicetree.c',
        'disk.c',
        'efi-string.c',
        'graphics.c',
        'initrd.c',
        'measure.c',
        'pe.c',
        'secure-boot.c',
        'ticks.c',
        'util.c',
)

systemd_boot_sources = files(
        'boot.c',
        'drivers.c',
        'random-seed.c',
        'vmm.c',
        'shim.c',
        'xbootldr.c',
)

stub_sources = files(
        'cpio.c',
        'linux.c',
        'splash.c',
        'stub.c',
)

if efi_arch[1] in ['ia32', 'x86_64']
        stub_sources += files('linux_x86.c')
endif

tests += [
        [files('test-efi-string.c', 'efi-string.c')],
]

# BCD parser only makes sense on arches that Windows supports.
if efi_arch[1] in ['ia32', 'x86_64', 'arm', 'aarch64']
        systemd_boot_sources += files('bcd.c')
        tests += [
                [files('test-bcd.c', 'efi-string.c'),
                 [],
                 [libzstd],
                 [],
                 'HAVE_ZSTD'],
        ]
        fuzzers += [
                [files('fuzz-bcd.c', 'bcd.c', 'efi-string.c')],
                [files('fuzz-efi-string.c', 'efi-string.c')],
        ]
endif

systemd_boot_objects = []
stub_objects = []
foreach file : fundamental_source_paths + common_sources + systemd_boot_sources + stub_sources
        # FIXME: replace ''.format(file) with fs.name(file) when meson_version requirement is >= 0.59.0
        o_file = custom_target('@0@.o'.format(file).split('/')[-1],
                               input : file,
                               output : '@0@.o'.format(file).split('/')[-1],
                               command : [cc.cmd_array(), '-c', '@INPUT@', '-o', '@OUTPUT@', efi_cflags],
                               depend_files : efi_headers + fundamental_headers)
        if (fundamental_source_paths + common_sources + systemd_boot_sources).contains(file)
                systemd_boot_objects += o_file
        endif
        if (fundamental_source_paths + common_sources + stub_sources).contains(file)
                stub_objects += o_file
        endif
endforeach

foreach tuple : [['systemd-boot@0@.@1@', systemd_boot_objects, false, 'systemd-boot'],
                 ['linux@0@.@1@.stub', stub_objects, true, 'systemd-stub']]
        elf = custom_target(
                tuple[0].format(efi_arch[0], 'elf'),
                input : tuple[1],
                output : tuple[0].format(efi_arch[0], 'elf'),
                command : [cc.cmd_array(),
                           '-o', '@OUTPUT@',
                           efi_cflags,
                           efi_ldflags,
                           '@INPUT@',
                           '-lefi',
                           '-lgnuefi',
                           '-lgcc'],
                install : tuple[2],
                install_tag: tuple[3],
                install_dir : bootlibdir)

        efi = custom_target(
                tuple[0].format(efi_arch[0], 'efi'),
                input : elf,
                output : tuple[0].format(efi_arch[0], 'efi'),
                command : [objcopy,
                           '-j', '.bss*',
                           '-j', '.data',
                           '-j', '.dynamic',
                           '-j', '.dynsym',
                           '-j', '.osrel',
                           '-j', '.rel*',
                           '-j', '.sbat',
                           '-j', '.sdata',
                           '-j', '.sdmagic',
                           '-j', '.text',
                           '--section-alignment=512',
                           efi_format,
                           '@INPUT@', '@OUTPUT@'],
                install : true,
                install_tag: tuple[3],
                install_dir : bootlibdir)

        alias_target(tuple[3], efi)
endforeach
