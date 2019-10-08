# SPDX-License-Identifier: LGPL-2.1+

hwdb_files = files('''
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
        60-evdev.hwdb
        60-keyboard.hwdb
        60-sensor.hwdb
        70-joystick.hwdb
        70-mouse.hwdb
        70-pointingstick.hwdb
        70-touchpad.hwdb
'''.split())

if conf.get('ENABLE_HWDB') == 1
        install_data(hwdb_files,
                     install_dir : udevhwdbdir)

        meson.add_install_script('sh', '-c',
                                 mkdir_p.format(join_paths(sysconfdir, 'udev/hwdb.d')))

        meson.add_install_script('sh', '-c',
                                 'test -n "$DESTDIR" || @0@/systemd-hwdb update'
                                 .format(rootbindir))
endif

############################################################

parse_hwdb_py = find_program('parse_hwdb.py')
if want_tests != 'false'
        test('parse-hwdb',
             parse_hwdb_py,
             timeout : 90)
endif

############################################################

run_target(
        'hwdb-update',
        command : [hwdb_update_sh, meson.current_source_dir()])
