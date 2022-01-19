# SPDX-License-Identifier: LGPL-2.1-or-later

conf.set10('ENABLE_EFI', get_option('efi'))
conf.set10('HAVE_GNU_EFI', false)

if not get_option('efi') or get_option('gnu-efi') == 'false'
        if get_option('gnu-efi') == 'true'
                error('gnu-efi support requested, but general efi support is disabled')
        endif
        subdir_done()
endif

efi_arch = {
        # host_cc_arch: [efi_arch (see Table 3-2 in UEFI spec), gnu_efi_inc_arch]
        'x86':     ['ia32', 'ia32'],
        'x86_64':  ['x64', 'x86_64'],
        'arm':     ['arm', 'arm'],
        'aarch64': ['aa64', 'aarch64'],
        'riscv64': ['riscv64', 'riscv64'],
}.get(host_machine.cpu_family(), [])

efi_incdir = get_option('efi-includedir')
if efi_arch.length() > 0 and not cc.has_header('@0@/@1@/efibind.h'.format(efi_incdir, efi_arch[1]))
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
                args: ['-nostdlib', '-ffreestanding', '-fshort-wchar'],
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
                warning('Not using @0@ as efi-ld, falling back to bfd'.format(efi_ld))
                efi_ld = 'bfd'
        endif
endif

efi_libdir = ''
foreach dir : [get_option('efi-libdir'),
               '/usr/lib/gnuefi' / efi_arch[0],
               run_command(
                        'realpath', '-e',
                        '/usr/lib' / run_command(cc.cmd_array(), '-print-multi-os-directory', check: false).stdout().strip(),
                        check: false
               ).stdout().strip()]
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

efi_cflags = cc.get_supported_arguments(
        basic_disabled_warnings +
        possible_common_cc_flags + [
                '-fno-stack-protector',
                '-fno-strict-aliasing',
                '-fpic',
                '-fwide-exec-charset=UCS2',
                '-Wall',
                '-Wextra',
                '-Wsign-compare',
        ]
) + [
        '-nostdlib',
        '-std=gnu99',
        '-ffreestanding',
        '-fshort-wchar',
        '-fvisibility=hidden',
        '-isystem', efi_incdir,
        '-isystem', efi_incdir / efi_arch[1],
        '-I', fundamental_path,
        '-DSD_BOOT',
        '-DGNU_EFI_USE_MS_ABI',
        '-include', efi_config_h,
        '-include', version_h,
]

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
if get_option('debug')
        efi_cflags += ['-ggdb', '-DEFI_DEBUG']
endif
if get_option('optimization') != '0'
        efi_cflags += ['-O' + get_option('optimization')]
endif
if get_option('b_ndebug') == 'true' or (
   get_option('b_ndebug') == 'if-release' and get_option('buildtype') in ['plain', 'release'])
        efi_cflags += ['-DNDEBUG']
endif
if get_option('b_lto')
        efi_cflags += ['-flto']
endif

foreach arg : get_option('c_args')
        if arg in [
                '-DNDEBUG',
                '-fno-lto',
                '-g', '-ggdb',
                '-O1', '-O2', '-O3', '-Og', '-Os',
                '-Werror',
           ] or arg.split('=')[0] in [
                '-ffile-prefix-map',
                '-flto',
           ]

                message('Using "@0@" from c_args for EFI compiler'.format(arg))
                efi_cflags += arg
        endif
endforeach

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
        # On arm, the compiler (correctly) gives us the following warning:
        #    libgcc.a(_popcountsi2.o) uses 4-byte wchar_t yet the output is to
        #    use 2-byte wchar_t; use of wchar_t values across objects may fail
        #
        # libgcc does not have any occurrences of wchar_t in its sources or the
        # documentation, so it's safe to assume that we can ignore this warning.
        #
        # So far, this only happens with arm due to popcount even though x86 and
        # x86_64 also have to rely on libgcc's popcount. Therefore, we only disable
        # this for arm to make sure this doesn't mask other issues in the future.
        efi_ldflags += ['-Wl,--no-warn-mismatch']
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
        'graphics.h',
        'linux.h',
        'measure.h',
        'missing_efi.h',
        'pe.h',
        'random-seed.h',
        'shim.h',
        'splash.h',
        'util.h',
        'xbootldr.h',
)

common_sources = files(
        'assert.c',
        'devicetree.c',
        'disk.c',
        'graphics.c',
        'measure.c',
        'pe.c',
        'secure-boot.c',
        'util.c',
)

systemd_boot_sources = files(
        'boot.c',
        'console.c',
        'drivers.c',
        'random-seed.c',
        'shim.c',
        'xbootldr.c',
)

stub_sources = files(
        'cpio.c',
        'initrd.c',
        'splash.c',
        'stub.c',
)

if efi_arch[1] in ['ia32', 'x86_64']
        stub_sources += files('linux_x86.c')
else
        stub_sources += files('linux.c')
endif

# BCD parser only makes sense on arches that Windows supports.
if efi_arch[1] in ['ia32', 'x86_64', 'arm', 'aarch64']
        systemd_boot_sources += files('bcd.c')
        tests += [
                [files('test-bcd.c'),
                 [],
                 [libzstd],
                 [],
                 'HAVE_ZSTD'],
        ]
        fuzzers += [
                [files('fuzz-bcd.c')],
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

systemd_boot_efi_name = 'systemd-boot@0@.efi'.format(efi_arch[0])
stub_elf_name = 'linux@0@.elf.stub'.format(efi_arch[0])
stub_efi_name = 'linux@0@.efi.stub'.format(efi_arch[0])

efi_stubs = []
foreach tuple : [['systemd_boot.so', systemd_boot_efi_name, systemd_boot_objects, false],
                 [stub_elf_name, stub_efi_name, stub_objects, true]]
        so = custom_target(
                tuple[0],
                input : tuple[2],
                output : tuple[0],
                command : [cc.cmd_array(), '-o', '@OUTPUT@', efi_ldflags, efi_cflags, tuple[2], '-lefi', '-lgnuefi', '-lgcc'],
                install : tuple[3],
                install_dir : bootlibdir)

        stub = custom_target(
                tuple[1],
                input : so,
                output : tuple[1],
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
                install_dir : bootlibdir)

        efi_stubs += [[so, stub]]
endforeach

############################################################

test_efi_disk_img = custom_target(
        'test-efi-disk.img',
        input : [efi_stubs[0][0], efi_stubs[1][1]],
        output : 'test-efi-disk.img',
        command : [test_efi_create_disk_sh, '@OUTPUT@','@INPUT@', splash_bmp])
