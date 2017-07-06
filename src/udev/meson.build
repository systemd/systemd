udevadm_sources = files('''
        udevadm.c
        udevadm-info.c
        udevadm-control.c
        udevadm-monitor.c
        udevadm-hwdb.c
        udevadm-settle.c
        udevadm-trigger.c
        udevadm-test.c
        udevadm-test-builtin.c
        udevadm-util.c
        udevadm-util.h
'''.split())

systemd_udevd_sources = files('udevd.c')

libudev_core_sources = '''
        udev.h
        udev-event.c
        udev-watch.c
        udev-node.c
        udev-rules.c
        udev-ctrl.c
        udev-builtin.c
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
        net/ethtool-util.c
        net/ethtool-util.h
'''.split()

if conf.get('HAVE_KMOD', false)
        libudev_core_sources += ['udev-builtin-kmod.c']
endif

if conf.get('HAVE_BLKID', false)
        libudev_core_sources += ['udev-builtin-blkid.c']
endif

if conf.get('HAVE_ACL', false)
        libudev_core_sources += ['udev-builtin-uaccess.c',
	                         logind_acl_c,
                                 sd_login_c]
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
                          libsystemd_internal]
        udev_rpath = ''
endif

libudev_internal = static_library(
        'udev',
        libudev_sources,
        include_directories : includes,
        link_with : udev_link_with)

libudev_core_includes = [includes, include_directories('net')]
libudev_core = static_library(
        'udev-core',
        libudev_core_sources,
        link_config_gperf_c,
        keyboard_keys_from_name_h,
        include_directories : libudev_core_includes,
        link_with : udev_link_with,
        dependencies : [libblkid, libkmod])

foreach prog : [['ata_id/ata_id.c'],
                ['cdrom_id/cdrom_id.c'],
                ['collect/collect.c'],
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
                   link_with : [libudev_internal],
                   install_rpath : udev_rpath,
                   install : true,
                   install_dir : udevlibexecdir)
endforeach

install_data('udev.conf',
             install_dir : join_paths(sysconfdir, 'udev'))

udev_pc = configure_file(
        input : 'udev.pc.in',
        output : 'udev.pc',
        configuration : substs)
install_data(udev_pc,
             install_dir : pkgconfigdatadir)

meson.add_install_script('sh', '-c',
                         mkdir_p.format(join_paths(sysconfdir, 'udev/rules.d')))
