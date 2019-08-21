# SPDX-License-Identifier: LGPL-2.1+

udevadm_sources = files('''
        udevadm.c
        udevadm.h
        udevadm-control.c
        udevadm-hwdb.c
        udevadm-info.c
        udevadm-monitor.c
        udevadm-settle.c
        udevadm-test.c
        udevadm-test-builtin.c
        udevadm-trigger.c
        udevadm-util.c
        udevadm-util.h
'''.split())

systemd_udevd_sources = files('udevd.c')

libudev_core_sources = '''
        udev-ctrl.c
        udev-ctrl.h
        udev-event.c
        udev-event.h
        udev-node.c
        udev-node.h
        udev-rules.c
        udev-rules.h
        udev-watch.c
        udev-watch.h
        udev-builtin.c
        udev-builtin.h
        udev-builtin-btrfs.c
        udev-builtin-hwdb.c
        udev-builtin-input_id.c
        udev-builtin-keyboard.c
        udev-builtin-net_id.c
        udev-builtin-net_setup_link.c
        udev-builtin-path_id.c
        udev-builtin-usb_id.c
        net/link-config.c
        net/link-config.h
        net/naming-scheme.c
        net/naming-scheme.h
'''.split()

if conf.get('HAVE_KMOD') == 1
        libudev_core_sources += ['udev-builtin-kmod.c']
endif

if conf.get('HAVE_BLKID') == 1
        libudev_core_sources += ['udev-builtin-blkid.c']
endif

if conf.get('HAVE_ACL') == 1
        libudev_core_sources += ['udev-builtin-uaccess.c',
                                 logind_acl_c,
                                 sd_login_sources]
endif

############################################################

generate_keyboard_keys_list = find_program('generate-keyboard-keys-list.sh')
keyboard_keys_list_txt = custom_target(
        'keyboard-keys-list.txt',
        output : 'keyboard-keys-list.txt',
        command : [generate_keyboard_keys_list, cpp],
        capture : true)

generate_keyboard_keys_gperf = find_program('generate-keyboard-keys-gperf.sh')
fname = 'keyboard-keys-from-name.gperf'
gperf_file = custom_target(
        fname,
        input : keyboard_keys_list_txt,
        output : fname,
        command : [generate_keyboard_keys_gperf, '@INPUT@'],
        capture : true)

fname = 'keyboard-keys-from-name.h'
keyboard_keys_from_name_h = custom_target(
        fname,
        input : gperf_file,
        output : fname,
        command : [gperf,
                   '-L', 'ANSI-C', '-t',
                   '-N', 'keyboard_lookup_key',
                   '-H', 'hash_key_name',
                   '-p', '-C',
                   '@INPUT@'],
        capture : true)

############################################################

link_config_gperf_c = custom_target(
        'link-config-gperf.c',
        input : 'net/link-config-gperf.gperf',
        output : 'link-config-gperf.c',
        command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

############################################################

if get_option('link-udev-shared')
        udev_link_with = [libshared]
        udev_rpath = rootlibexecdir
else
        udev_link_with = [libshared_static,
                          libsystemd_static]
        udev_rpath = ''
endif

libudev_basic = static_library(
        'udev-basic',
        libudev_sources,
        include_directories : includes,
        c_args : ['-fvisibility=default'])

libudev_static = static_library(
        'udev_static',
        include_directories : includes,
        link_with : udev_link_with,
        link_whole : libudev_basic)

static_libudev = get_option('static-libudev')
static_libudev_pic = static_libudev == 'true' or static_libudev == 'pic'
install_libudev_static = static_library(
        'udev',
        basic_sources,
        shared_sources,
        libsystemd_sources,
        libudev_sources,
        disable_mempool_c,
        include_directories : includes,
        build_by_default : static_libudev != 'false',
        install : static_libudev != 'false',
        install_dir : rootlibdir,
        link_depends : libudev_sym,
        dependencies : libshared_deps + [libmount],
        c_args : static_libudev_pic ? [] : ['-fno-PIC'],
        pic : static_libudev_pic)

libudev = shared_library(
        'udev',
        disable_mempool_c,
        version : libudev_version,
        include_directories : includes,
        link_args : ['-shared',
                     '-Wl,--version-script=' + libudev_sym_path],
        link_with : [libsystemd_static, libshared_static],
        link_whole : libudev_basic,
        dependencies : [threads],
        link_depends : libudev_sym,
        install : true,
        install_dir : rootlibdir)

libudev_core_includes = [includes, include_directories('net')]
libudev_core = static_library(
        'udev-core',
        libudev_core_sources,
        link_config_gperf_c,
        keyboard_keys_from_name_h,
        include_directories : libudev_core_includes,
        c_args : ['-DLOG_REALM=LOG_REALM_UDEV'],
        link_with : udev_link_with,
        dependencies : [libblkid, libkmod])

foreach prog : [['ata_id/ata_id.c'],
                ['cdrom_id/cdrom_id.c'],
                ['fido_id/fido_id.c',
                 'fido_id/fido_id_desc.c',
                 'fido_id/fido_id_desc.h'],
                ['scsi_id/scsi_id.c',
                 'scsi_id/scsi_id.h',
                 'scsi_id/scsi_serial.c',
                 'scsi_id/scsi.h'],
                ['v4l_id/v4l_id.c'],
                ['mtd_probe/mtd_probe.c',
                 'mtd_probe/mtd_probe.h',
                 'mtd_probe/probe_smartmedia.c']]

        executable(prog[0].split('/')[0],
                   prog,
                   include_directories : includes,
                   c_args : ['-DLOG_REALM=LOG_REALM_UDEV'],
                   dependencies : [versiondep],
                   link_with : [libudev_static],
                   install_rpath : udev_rpath,
                   install : true,
                   install_dir : udevlibexecdir)
endforeach

install_data('udev.conf',
             install_dir : join_paths(sysconfdir, 'udev'))

configure_file(
        input : 'udev.pc.in',
        output : 'udev.pc',
        configuration : substs,
        install_dir : pkgconfigdatadir == 'no' ? '' : pkgconfigdatadir)

meson.add_install_script('sh', '-c',
                         mkdir_p.format(join_paths(sysconfdir, 'udev/rules.d')))

fuzzers += [
        [['src/udev/net/fuzz-link-parser.c',
          'src/fuzz/fuzz.h'],
         [libudev_core,
          libudev_static,
          libsystemd_network,
          libshared],
         [threads,
          libacl]]
        ]
