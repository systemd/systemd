# SPDX-License-Identifier: LGPL-2.1-or-later

install_data(
        'README',
        install_dir : udevrulesdir)

rules = [
        [files('60-autosuspend.rules',
               '60-block.rules',
               '60-cdrom_id.rules',
               '60-drm.rules',
               '60-evdev.rules',
               '60-fido-id.rules',
               '60-infiniband.rules',
               '60-input-id.rules',
               '60-persistent-alsa.rules',
               '60-persistent-input.rules',
               '60-persistent-storage.rules',
               '60-persistent-storage-tape.rules',
               '60-persistent-v4l.rules',
               '60-sensor.rules',
               '60-serial.rules',
               '70-camera.rules',
               '70-joystick.rules',
               '70-mouse.rules',
               '70-touchpad.rules',
               '75-net-description.rules',
               '75-probe_mtd.rules',
               '78-sound-card.rules',
               '80-net-setup-link.rules',
               '81-net-dhcp.rules',
              )],

        [files('80-drivers.rules'),
         conf.get('HAVE_KMOD') == 1],

        [files('70-memory.rules'),
         dmi_arches.contains(host_machine.cpu_family())],

        [files('70-power-switch.rules'),
         enable_logind],
]

all_rules = []

foreach tuple : rules
        if tuple.length() == 1 or tuple[1]
                install_data(tuple[0],
                             install_dir : udevrulesdir)
                all_rules += tuple[0]
        endif
endforeach

rules_in = [
        ['50-udev-default.rules'],
        ['64-btrfs.rules'],
        ['99-systemd.rules'],

        ['70-uaccess.rules',   enable_logind and conf.get('HAVE_ACL') == 1],
        ['71-seat.rules',      enable_logind],
        ['73-seat-late.rules', enable_logind],

        ['90-vconsole.rules',  conf.get('ENABLE_VCONSOLE') == 1],
]

foreach tuple : rules_in
        want = tuple.length() == 1 or tuple[1]

        rule = custom_target(
                tuple[0],
                input : tuple[0] + '.in',
                output: tuple[0],
                command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
                install : want,
                install_dir : udevrulesdir)

        if want
                all_rules += rule
        endif
endforeach
