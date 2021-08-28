# SPDX-License-Identifier: LGPL-2.1-or-later

# Those files right now are not supported by the grammar. Also,
# they are very long but quite repetitive and the parser is not very fast.
# So we don't "test" them.
hwdb_files_notest = files('''
        README
        20-dmi-id.hwdb
        20-pci-vendor-model.hwdb
        20-pci-classes.hwdb
        20-usb-vendor-model.hwdb
        20-usb-classes.hwdb
        20-sdio-vendor-model.hwdb
        20-sdio-classes.hwdb
        20-bluetooth-vendor-product.hwdb
        20-acpi-vendor.hwdb
        20-OUI.hwdb
        20-net-ifname.hwdb
        20-vmbus-class.hwdb
'''.split())

hwdb_files_test = files('''
        60-autosuspend.hwdb
        60-autosuspend-fingerprint-reader.hwdb
        60-evdev.hwdb
        60-input-id.hwdb
        60-keyboard.hwdb
        60-seat.hwdb
        60-sensor.hwdb
        70-analyzers.hwdb
        70-av-production.hwdb
        70-cameras.hwdb
        70-joystick.hwdb
        70-mouse.hwdb
        70-pointingstick.hwdb
        70-touchpad.hwdb
        80-ieee1394-unit-function.hwdb
'''.split())

if conf.get('ENABLE_HWDB') == 1
        auto_suspend_rules = custom_target(
                '60-autosuspend-chromiumos.hwdb',
                output : '60-autosuspend-chromiumos.hwdb',
                command : make_autosuspend_rules_py,
                capture : true,
                install : true,
                install_dir: udevhwdbdir)

        install_data(hwdb_files_notest,
                     hwdb_files_test,
                     install_dir : udevhwdbdir)

        if install_sysconfdir
                meson.add_install_script('sh', '-c',
                                         mkdir_p.format(join_paths(sysconfdir, 'udev/hwdb.d')))

                meson.add_install_script('sh', '-c',
                                         'test -n "$DESTDIR" || @0@/systemd-hwdb update'.format(rootbindir))
        endif

        if want_tests != 'false'
                parse_hwdb_py = find_program('parse_hwdb.py')
                test('parse-hwdb',
                     parse_hwdb_py,
                     args : [hwdb_files_test,
                             auto_suspend_rules],
                     timeout : 90)
        endif
endif

############################################################

run_target(
        'update-hwdb',
        command : [update_hwdb_sh, meson.current_source_dir()])

run_target(
        'update-hwdb-autosuspend',
        command : [update_hwdb_autosuspend_sh, project_source_root])
