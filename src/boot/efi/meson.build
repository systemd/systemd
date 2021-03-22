# SPDX-License-Identifier: LGPL-2.1-or-later

efi_headers = files('''
        console.h
        crc32.h
        disk.h
        graphics.h
        linux.h
        measure.h
        missing_efi.h
        pe.h
        random-seed.h
        sha256.h
        shim.h
        splash.h
        util.h
'''.split())

common_sources = '''
        disk.c
        graphics.c
        measure.c
        pe.c
        secure-boot.c
        util.c
'''.split()

systemd_boot_sources = '''
        boot.c
        console.c
        crc32.c
        random-seed.c
        sha256.c
        shim.c
'''.split()

stub_sources = '''
        linux.c
        splash.c
        stub.c
'''.split()

if conf.get('ENABLE_EFI') == 1 and get_option('gnu-efi') != 'false'
        efi_cc = get_option('efi-cc')
        if efi_cc.length() == 0
                efi_cc = cc.cmd_array()
        endif

        efi_ld = find_program(get_option('efi-ld'), required: true)
        efi_ld_name = efi_ld.path().split('/')[-1]
        if efi_ld_name == 'lld' or efi_ld_name == 'ld.lld'
                # LLVM/LLD does not support PE/COFF relocations
                # https://lists.llvm.org/pipermail/llvm-dev/2021-March/149234.html
                error('LLVM/lld does not support PE/COFF relocations. Use different linker for EFI image.')
        endif

        efi_incdir = get_option('efi-includedir')

        gnu_efi_path_arch = ''
        foreach name : [gnu_efi_arch, EFI_MACHINE_TYPE_NAME]
                if (gnu_efi_path_arch == '' and name != '' and
                    cc.has_header('@0@/@1@/efibind.h'.format(efi_incdir, name)))
                        gnu_efi_path_arch = name
                endif
        endforeach

        if gnu_efi_path_arch != '' and EFI_MACHINE_TYPE_NAME == ''
                error('gnu-efi is available, but EFI_MACHINE_TYPE_NAME is unknown')
        endif

        efi_libdir = get_option('efi-libdir')
        if efi_libdir == ''
                # New location first introduced with gnu-efi 3.0.11
                efi_libdir = join_paths('/usr/lib/gnuefi', EFI_MACHINE_TYPE_NAME)
                cmd = run_command('test', '-e', efi_libdir)

                if cmd.returncode() != 0
                        # Fall back to the old approach
                        cmd = run_command(efi_cc + ['-print-multi-os-directory'])
                        if cmd.returncode() == 0
                                path = join_paths('/usr/lib', cmd.stdout().strip())
                                cmd = run_command('realpath', '-e', path)
                                if cmd.returncode() == 0
                                        efi_libdir = cmd.stdout().strip()
                                endif
                        endif
                endif
        endif

        have_gnu_efi = gnu_efi_path_arch != '' and efi_libdir != ''
else
        have_gnu_efi = false
endif

if get_option('gnu-efi') == 'true' and not have_gnu_efi
        error('gnu-efi support requested, but headers were not found')
endif

if have_gnu_efi
        efi_conf = configuration_data()
        efi_conf.set_quoted('EFI_MACHINE_TYPE_NAME', EFI_MACHINE_TYPE_NAME)
        efi_conf.set10('ENABLE_TPM', get_option('tpm'))
        efi_conf.set('SD_TPM_PCR', get_option('tpm-pcrindex'))

        efi_config_h = configure_file(
                output : 'efi_config.h',
                configuration : efi_conf)

        objcopy = find_program('objcopy')

        efi_location_map = [
                # New locations first introduced with gnu-efi 3.0.11
                [join_paths(efi_libdir, 'efi.lds'),
                 join_paths(efi_libdir, 'crt0.o')],
                # Older locations...
                [join_paths(efi_libdir, 'gnuefi', 'elf_@0@_efi.lds'.format(gnu_efi_path_arch)),
                 join_paths(efi_libdir, 'gnuefi', 'crt0-efi-@0@.o'.format(gnu_efi_path_arch))],
                [join_paths(efi_libdir, 'elf_@0@_efi.lds'.format(gnu_efi_path_arch)),
                 join_paths(efi_libdir, 'crt0-efi-@0@.o'.format(gnu_efi_path_arch))]]
        efi_lds = ''
        foreach location : efi_location_map
                if efi_lds == ''
                        cmd = run_command('test', '-f', location[0])
                        if cmd.returncode() == 0
                                efi_lds = location[0]
                                efi_crt0 = location[1]
                        endif
                endif
        endforeach
        if efi_lds == ''
                if get_option('gnu-efi') == 'true'
                        error('gnu-efi support requested, but cannot find efi.lds')
                else
                        have_gnu_efi = false
                endif
        endif
endif

if have_gnu_efi
        compile_args = ['-Wall',
                        '-Wextra',
                        '-std=gnu99',
                        '-nostdlib',
                        '-fpic',
                        '-fshort-wchar',
                        '-ffreestanding',
                        '-fno-strict-aliasing',
                        '-fno-stack-protector',
                        '-Wsign-compare',
                        '-Wno-missing-field-initializers',
                        '-isystem', efi_incdir,
                        '-isystem', join_paths(efi_incdir, gnu_efi_path_arch),
                        '-I', fundamental_path,
                        '-DSD_BOOT',
                        '-include', efi_config_h,
                        '-include', version_h]
        if efi_arch == 'x86_64'
                compile_args += ['-mno-red-zone',
                                 '-mno-sse',
                                 '-mno-mmx',
                                 '-DEFI_FUNCTION_WRAPPER',
                                 '-DGNU_EFI_USE_MS_ABI']
        elif efi_arch == 'ia32'
                compile_args += ['-mno-sse',
                                 '-mno-mmx']
        elif efi_arch == 'arm'
                if cc.has_argument('-mgeneral-regs-only')
                        compile_args += ['-mgeneral-regs-only']
                endif

                if cc.has_argument('-mfpu=none')
                        compile_args += ['-mfpu=none']
                endif
        endif
        if get_option('werror') == true
                compile_args += ['-Werror']
        endif
        if get_option('buildtype') == 'debug'
                compile_args += ['-ggdb', '-O0']
        elif get_option('buildtype') == 'debugoptimized'
                compile_args += ['-ggdb', '-Og']
        else
                compile_args += ['-O2']
        endif

        efi_ldflags = ['-T', efi_lds,
                       '-shared',
                       '-Bsymbolic',
                       '-nostdlib',
                       '-znocombreloc',
                       '-L', efi_libdir,
                       efi_crt0]
        if efi_arch == 'aarch64' or efi_arch == 'arm'
                # Aarch64 and ARM32 don't have an EFI capable objcopy. Use 'binary'
                # instead, and add required symbols manually.
                efi_ldflags += ['--defsym=EFI_SUBSYSTEM=0xa']
                efi_format = ['-O', 'binary']
        else
                efi_format = ['--target=efi-app-@0@'.format(gnu_efi_arch)]
        endif

        systemd_boot_objects = []
        stub_objects = []
        foreach file : fundamental_source_paths + common_sources + systemd_boot_sources + stub_sources
                o_file = custom_target(file.split('/')[-1] + '.o',
                                       input : file,
                                       output : file.split('/')[-1] + '.o',
                                       command : efi_cc + ['-c', '@INPUT@', '-o', '@OUTPUT@']
                                                 + compile_args,
                                       depend_files : efi_headers + fundamental_headers)
                if (fundamental_source_paths + common_sources + systemd_boot_sources).contains(file)
                        systemd_boot_objects += o_file
                endif
                if (fundamental_source_paths + common_sources + stub_sources).contains(file)
                        stub_objects += o_file
                endif
        endforeach

        libgcc_file_name = run_command(efi_cc + ['-print-libgcc-file-name']).stdout().strip()
        systemd_boot_efi_name = 'systemd-boot@0@.efi'.format(EFI_MACHINE_TYPE_NAME)
        stub_efi_name = 'linux@0@.efi.stub'.format(EFI_MACHINE_TYPE_NAME)
        no_undefined_symbols = find_program('no-undefined-symbols.sh')

        foreach tuple : [['systemd_boot.so', systemd_boot_efi_name, systemd_boot_objects],
                         ['stub.so', stub_efi_name, stub_objects]]
                so = custom_target(
                        tuple[0],
                        input : tuple[2],
                        output : tuple[0],
                        command : [efi_ld, '-o', '@OUTPUT@'] +
                                  efi_ldflags + tuple[2] +
                                  ['-lefi', '-lgnuefi', libgcc_file_name])

                if want_tests != 'false'
                        test('no-undefined-symbols-' + tuple[0],
                             no_undefined_symbols,
                             args : [so])
                endif

                stub = custom_target(
                        tuple[1],
                        input : so,
                        output : tuple[1],
                        command : [objcopy,
                                   '-j', '.text',
                                   '-j', '.sdata',
                                   '-j', '.data',
                                   '-j', '.dynamic',
                                   '-j', '.dynsym',
                                   '-j', '.rel*']
                                  + efi_format +
                                  ['@INPUT@', '@OUTPUT@'],
                        install : true,
                        install_dir : bootlibdir)

                set_variable(tuple[0].underscorify(), so)
                set_variable(tuple[0].underscorify() + '_stub', stub)
        endforeach

        ############################################################

        test_efi_disk_img = custom_target(
                'test-efi-disk.img',
                input : [systemd_boot_so, stub_so_stub],
                output : 'test-efi-disk.img',
                command : [test_efi_create_disk_sh, '@OUTPUT@',
                           '@INPUT0@', '@INPUT1@', splash_bmp])
endif
