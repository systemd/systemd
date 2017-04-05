# -*- mode: meson -*-

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

if conf.get('HAVE_KMOD', 0) == 1
  libudev_core_sources += ['udev-builtin-kmod.c']
endif

if conf.get('HAVE_BLKID', 0) == 1
  libudev_core_sources += ['udev-builtin-blkid.c']
endif

if conf.get('HAVE_ACL', 0) == 1
  libudev_core_sources += ['udev-builtin-uaccess.c',
	                   logind_acl_c,
                           sd_login_c]
endif

############################################################

generate_keyboard_keys_list = find_program('generate-keyboard-keys-list.sh')
keyboard_keys_list_txt = custom_target(
    'keyboard-keys-list.txt',
    output : 'keyboard-keys-list.txt',
    command : [generate_keyboard_keys_list],
    capture : true)

fname = 'keyboard-keys-from-name.gperf'
gperf_file = custom_target(
    fname,
    input : keyboard_keys_list_txt,
    output : fname,
    command : [generate_gperfs, 'key', '', '@INPUT@'],
    capture : true)

fname = 'keyboard-keys-from-name.h'
keyboard_keys_from_name_h = custom_target(
    fname,
    input : gperf_file,
    output : fname,
    command : [gperf,
               '-L', 'ANSI-C', '-t', '--ignore-case',
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

libudev_core = static_library(
    'udev-core',
    libudev_core_sources,
    link_config_gperf_c,
    keyboard_keys_from_name_h,
    include_directories : [includes, include_directories('net')],
    link_with : [libshared])

executable('ata_id',
           'ata_id/ata_id.c',
           include_directories : includes,
           link_with : [libudev_internal,
                        libshared],
           install : true,
           install_dir : udevlibexecdir)

executable('cdrom_id',
           'cdrom_id/cdrom_id.c',
           include_directories : includes,
           link_with : [libudev_internal,
                        libshared],
           install : true,
           install_dir : udevlibexecdir)

executable('collect',
           'collect/collect.c',
           include_directories : includes,
           link_with : [libudev_internal,
                        libshared],
           install : true,
           install_dir : udevlibexecdir)

executable('scsi_id',
           'scsi_id/scsi_id.c',
           'scsi_id/scsi_id.h',
           'scsi_id/scsi_serial.c',
           'scsi_id/scsi.h',
           include_directories : includes,
           link_with : [libudev_internal,
                        libshared],
           install : true,
           install_dir : udevlibexecdir)

executable('v4l_id',
           'v4l_id/v4l_id.c',
           include_directories : includes,
           link_with : [libudev_internal,
                        libshared],
           install : true,
           install_dir : udevlibexecdir)

executable('mtd_probe',
           'mtd_probe/mtd_probe.c',
           'mtd_probe/mtd_probe.h',
           'mtd_probe/probe_smartmedia.c',
           include_directories : includes,
           link_with : [libudev_internal,
                        libshared],
           install : true,
           install_dir : udevlibexecdir)

install_data('udev.conf',
             install_dir : sysconfdir + '/udev')

udev_pc = configure_file(
    input : 'udev.pc.in',
    output : 'udev.pc',
    configuration : substs)
install_data(udev_pc,
             install_dir : pkgconfigdatadir)
