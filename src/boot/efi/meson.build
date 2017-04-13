efi_headers = files('''
  console.h
  disk.h
  graphics.h
  linux.h
  measure.h
  pefile.h
  splash.h
  util.h
'''.split())

common_sources = '''
  disk.c
  graphics.c
  measure.c
  pefile.c
  util.c
'''.split()

systemd_boot_sources = '''
  boot.c
  console.c
'''.split()

stub_sources = '''
  linux.c
  splash.c
  stub.c
'''.split()

if conf.get('ENABLE_EFI', 0) == 1 and get_option('gnu-efi') != 'no'
  efi_cc = get_option('efi-cc')
  efi_ld = get_option('efi-ld')

  efibind_h = 'efi/@0@/efibind.h'.format(efi_arch)
  have_header = cc.has_header(efibind_h)

  if have_header and EFI_MACHINE_TYPE_NAME == ''
    error('gnu-efi is available, but EFI_MACHINE_TYPE_NAME is unknown')
  endif

  efi_libdir = get_option('efi-libdir')
  if efi_libdir == ''
    cmd = 'cd /usr/lib/$(@0@ -print-multi-os-directory) && pwd'.format(efi_cc)
    ret = run_command('sh', '-c', cmd)
    if ret.returncode() == 0
      efi_libdir = ret.stdout().strip()
    endif
  endif

  have_gnu_efi = have_header and efi_libdir != ''
else
  have_gnu_efi = false
endif

if get_option('gnu-efi') == 'yes' and not have_gnu_efi
  error('gnu-efi support requested, but headers were not found')
endif

if have_gnu_efi
  efi_conf = configuration_data()
  efi_conf.set_quoted('PACKAGE_VERSION', meson.project_version())
  efi_conf.set_quoted('EFI_MACHINE_TYPE_NAME', EFI_MACHINE_TYPE_NAME)

  efi_config_h = configure_file(
    output : 'efi_config.h',
    configuration : efi_conf)

  objcopy = find_program('objcopy')

  efi_ldsdir = get_option('efi-ldsdir')
  if efi_ldsdir == ''
    efi_ldsdir = join_paths(efi_libdir, 'gnuefi')
  endif

  efi_incdir = get_option('efi-includedir')

  message('efi-libdir: "@0@"'.format(efi_libdir))
  message('efi-ldsdir: "@0@"'.format(efi_ldsdir))
  message('efi-includedir: "@0@"'.format(efi_incdir))

  compile_args = ['-Wall',
                  '-Wextra',
                  '-std=gnu90',
                  '-nostdinc',
                  '-ggdb', '-O0',
                  '-fpic',
                  '-fshort-wchar',
                  '-ffreestanding',
                  '-fno-strict-aliasing',
                  '-fno-stack-protector',
                  '-Wsign-compare',
                  '-Wno-missing-field-initializers',
                  '-isystem', efi_incdir,
                  '-isystem', join_paths(efi_incdir, efi_arch),
                  '-include', efi_config_h]
  if efi_arch == 'x86_64'
    compile_args += ['-mno-red-zone',
                     '-mno-sse',
                     '-mno-mmx',
                     '-DEFI_FUNCTION_WRAPPER',
                     '-DGNU_EFI_USE_MS_ABI']
  elif efi_arch == 'ia32'
    compile_args += ['-mno-sse',
                     '-mno-mmx']
  endif

  efi_ldflags = ['-T',
                 '@0@/elf_@1@_efi.lds'.format(efi_ldsdir, efi_arch),
                 '-shared',
                 '-Bsymbolic',
                 '-nostdlib',
                 '-znocombreloc',
                 '-L', efi_libdir,
                 '@0@/crt0-efi-@1@.o'.format(efi_ldsdir, efi_arch)]
  if efi_arch == 'aarch64' or efi_arch == 'arm'
    # Aarch64 and ARM32 don't have an EFI capable objcopy. Use 'binary'
    # instead, and add required symbols manually.
    efi_ldflags += ['--defsym=EFI_SUBSYSTEM=0xa']
    efi_format = ['-O', 'binary']
  else
    efi_format = ['--target=efi-app-@0@'.format(efi_arch)]
  endif

  systemd_boot_objects = []
  stub_objects = []
  foreach file : common_sources + systemd_boot_sources + stub_sources
    o_file = custom_target(file + '.o',
                           input : file,
                           output : file + '.o',
                           command : [efi_cc, '-c', '@INPUT@', '-o', '@OUTPUT@']
                                     + compile_args,
                           depend_files : efi_headers)
    if (common_sources + systemd_boot_sources).contains(file)
      systemd_boot_objects += [o_file]
    endif
    if (common_sources + stub_sources).contains(file)
      stub_objects += [o_file]
    endif
  endforeach

  libgcc_file_name = run_command(efi_cc, '-print-libgcc-file-name').stdout().strip()
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

    test('no-undefined-symbols-' + tuple[0],
         no_undefined_symbols,
         args : [so])

    custom_target(
      tuple[1],
      input : so,
      output : tuple[1],
      command : [objcopy,
                 '-j', '.text',
                 '-j', '.sdata',
                 '-j', '.data',
                 '-j', '.dynamic',
                 '-j', '.dynsym',
                 '-j', '.rel',
                 '-j', '.rela',
                 '-j', '.reloc']
                + efi_format +
                ['@INPUT@', '@OUTPUT@'],
      install : true,
      install_dir : bootlibdir)
  endforeach
endif
