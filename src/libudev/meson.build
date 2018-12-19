# SPDX-License-Identifier: LGPL-2.1+

libudev_sources = files('''
        libudev.c
        libudev-device.c
        libudev-device-internal.h
        libudev-enumerate.c
        libudev-hwdb.c
        libudev-list.c
        libudev-list-internal.h
        libudev-monitor.c
        libudev-queue.c
        libudev-util.c
        libudev-util.h
'''.split())

############################################################

libudev_sym = files('libudev.sym')
libudev_sym_path = meson.current_source_dir() + '/libudev.sym'

install_headers('libudev.h')
libudev_h_path = '@0@/libudev.h'.format(meson.current_source_dir())

pc_in = configure_file(
        input : 'libudev.pc.in.in',
        output : 'libudev.pc.in',
        configuration : substs)
libudev_pc = custom_target(
        'libudev.pc',
        command: vcs_tagger + ['@INPUT@'],
        input : pc_in,
        output : 'libudev.pc',
        capture : true,
        build_always_stale : true,
        install : pkgconfiglibdir != 'no',
        install_dir : pkgconfiglibdir)
