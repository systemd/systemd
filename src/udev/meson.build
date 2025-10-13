# SPDX-License-Identifier: LGPL-2.1-or-later

udevadm_sources = files(
        'udevadm-cat.c',
        'udevadm-control.c',
        'udevadm-hwdb.c',
        'udevadm-info.c',
        'udevadm-lock.c',
        'udevadm-monitor.c',
        'udevadm-settle.c',
        'udevadm-test-builtin.c',
        'udevadm-test.c',
        'udevadm-trigger.c',
        'udevadm-util.c',
        'udevadm-verify.c',
        'udevadm-wait.c',
        'udevadm.c',
        'udevd.c',
)
udevadm_extract_sources = files(
        'net/link-config.c',
        'udev-builtin.c',
        'udev-builtin-btrfs.c',
        'udev-builtin-dissect_image.c',
        'udev-builtin-factory_reset.c',
        'udev-builtin-hwdb.c',
        'udev-builtin-input_id.c',
        'udev-builtin-keyboard.c',
        'udev-builtin-net_driver.c',
        'udev-builtin-net_id.c',
        'udev-builtin-net_setup_link.c',
        'udev-builtin-path_id.c',
        'udev-builtin-usb_id.c',
        'udev-config.c',
        'udev-ctrl.c',
        'udev-dump.c',
        'udev-error.c',
        'udev-event.c',
        'udev-format.c',
        'udev-manager.c',
        'udev-manager-ctrl.c',
        'udev-node.c',
        'udev-rules.c',
        'udev-spawn.c',
        'udev-varlink.c',
        'udev-watch.c',
        'udev-worker.c',
)

if conf.get('HAVE_KMOD') == 1
        udevadm_extract_sources += files('udev-builtin-kmod.c')
endif

if conf.get('HAVE_BLKID') == 1
        udevadm_extract_sources += files('udev-builtin-blkid.c')
endif

if conf.get('HAVE_ACL') == 1
        udevadm_extract_sources += files('udev-builtin-uaccess.c')
endif

############################################################

generate_keyboard_keys_list = files('generate-keyboard-keys-list.sh')
keyboard_keys_list_txt = custom_target(
        input : [generate_keyboard_keys_list, keyboard_sources],
        output : 'keyboard-keys-list.txt',
        command : [env, 'bash', generate_keyboard_keys_list, cpp, system_include_args],
        capture : true)

generate_keyboard_keys_gperf = files('generate-keyboard-keys-gperf.sh')
gperf_file = custom_target(
        input : [generate_keyboard_keys_gperf, keyboard_keys_list_txt],
        output : 'keyboard-keys-from-name.gperf',
        command : [env, 'bash', '@INPUT@'],
        capture : true)

keyboard_keys_from_name_inc = custom_target(
        input : gperf_file,
        output : 'keyboard-keys-from-name.inc',
        command : [gperf,
                   '-L', 'ANSI-C', '-t',
                   '-N', 'keyboard_lookup_key',
                   '-H', 'hash_key_name',
                   '-p', '-C',
                   '@INPUT@'],
        capture : true)

generated_sources += keyboard_keys_from_name_inc

############################################################

udev_link_gperf_gperf = files('net/link-config-gperf.gperf')

link_config_gperf_c = custom_target(
        input : udev_link_gperf_gperf,
        output : 'link-config-gperf.c',
        command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

udevadm_extract_sources += link_config_gperf_c
generated_sources += link_config_gperf_c

############################################################

if get_option('link-udev-shared')
        udev_link_with = [libshared]
        udev_rpath = pkglibdir
else
        udev_link_with = [libshared_static,
                          libsystemd_static]
        udev_rpath = ''
endif

############################################################

udev_dependencies = [
        libacl,
        libblkid,
        libkmod,
        threads,
]

udev_plugin_template = executable_template + {
        'public' : true,
        'link_with' : udev_link_with,
        'install_rpath' : udev_rpath,
        'install_dir' : udevlibexecdir,
        'install_tag' : 'udev',
}

udev_common_template = {
        'objects' : ['udevadm'],
        'dependencies' : [
                libacl,
                libblkid,
                threads,
        ],
}
udev_test_template = test_template + udev_common_template
udev_fuzz_template = fuzz_template + udev_common_template

udev_binaries_dict = [
        executable_template + {
                'name' : 'udevadm',
                'public' : true,
                'sources' : udevadm_sources +
                            udevadm_extract_sources +
                            keyboard_keys_from_name_inc,
                'include_directories' : [
                        libexec_template['include_directories'],
                        include_directories('.', 'net'),
                ],
                'dependencies' : udev_dependencies,
                'link_with' : udev_link_with,
                'install_rpath' : udev_rpath,
                'install_tag' : 'udev',
                'extract' : udevadm_extract_sources,
        },
        udev_plugin_template + {
                'name' : 'ata_id',
                'sources' : files('ata_id/ata_id.c'),
        },
        udev_plugin_template + {
                'name' : 'cdrom_id',
                'sources' : files('cdrom_id/cdrom_id.c'),
        },
        udev_plugin_template + {
                'name' : 'dmi_memory_id',
                'conditions' : ['HAVE_DMI'],
                'sources' : files('dmi_memory_id/dmi_memory_id.c'),
        },
        udev_plugin_template + {
                'name' : 'fido_id',
                'sources' : files(
                        'fido_id/fido_id.c',
                        'fido_id/fido_id_desc.c',
                ),
                'extract' : files('fido_id/fido_id_desc.c'),
        },
        udev_plugin_template + {
                'name' : 'iocost',
                'sources' : files('iocost/iocost.c'),
        },
        udev_plugin_template + {
                'name' : 'mtd_probe',
                'sources' : files(
                        'mtd_probe/mtd_probe.c',
                        'mtd_probe/probe_smartmedia.c',
                ),
        },
        udev_plugin_template + {
                'name' : 'scsi_id',
                'sources' : files(
                        'scsi_id/scsi_id.c',
                        'scsi_id/scsi_serial.c',
                ),
        },
        udev_plugin_template + {
                'name' : 'v4l_id',
                'sources' : files('v4l_id/v4l_id.c'),
        },
]
# For the udev alias
udev_binaries = []
foreach binary : udev_binaries_dict
        udev_binaries += binary.get('name')
endforeach

executables += udev_binaries_dict
executables += [
        test_template + {
                'sources' : files('fido_id/test-fido-id-desc.c'),
                'objects' : ['fido_id'],
                'suite' : 'udev',
        },
        udev_test_template + {
                'sources' : files('net/test-link-config-tables.c'),
                'suite' : 'udev',
        },
        udev_test_template + {
                'sources' : files('test-udev-builtin.c'),
        },
        udev_test_template + {
                'sources' : files('test-udev-format.c'),
        },
        udev_test_template + {
                'sources' : files('test-udev-manager.c'),
        },
        udev_test_template + {
                'sources' : files('test-udev-node.c'),
        },
        udev_test_template + {
                'sources' : files('test-udev-rule-runner.c'),
                'dependencies' : udev_dependencies + [
                        libselinux,
                ],
                'type' : 'manual',
        },
        udev_test_template + {
                'sources' : files('test-udev-rules.c'),
        },
        udev_test_template + {
                'sources' : files('test-udev-spawn.c'),
        },
        fuzz_template + {
                'sources' : files('fido_id/fuzz-fido-id-desc.c'),
                'objects' : ['fido_id'],
        },
        udev_fuzz_template + {
                'sources' : files('net/fuzz-link-parser.c'),
        },
        udev_fuzz_template + {
                'sources' : files('fuzz-udev-rule-parse-value.c'),
        },
        udev_fuzz_template + {
                'sources' : files('fuzz-udev-rules.c'),
        },
]

install_symlink('systemd-udevd',
                pointing_to : libexecdir_to_bin + 'udevadm',
                install_dir : libexecdir,
                install_tag : 'udev')

if install_sysconfdir_samples
        install_data('udev.conf',
                     install_dir : configfiledir / 'udev',
                     install_tag : 'udev')
        install_data('iocost/iocost.conf',
                     install_dir : configfiledir / 'udev',
                     install_tag : 'udev')
endif

udev_pc = custom_target(
        input : 'udev.pc.in',
        output : 'udev.pc',
        command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
        install : pkgconfigdatadir != 'no',
        install_tag : 'devel',
        install_dir : pkgconfigdatadir)

if install_sysconfdir
        install_emptydir(sysconfdir / 'udev/rules.d', install_tag : 'udev')
endif
