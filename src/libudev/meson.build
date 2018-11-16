# SPDX-License-Identifier: LGPL-2.1+

libudev_sources = files('''
        libudev-private.h
        libudev-device-internal.h
        libudev.c
        libudev-list.c
        libudev-util.c
        libudev-device.c
        libudev-enumerate.c
        libudev-monitor.c
        libudev-queue.c
        libudev-hwdb.c
'''.split())

############################################################

libudev_sym = files('libudev.sym')
libudev_sym_path = meson.current_source_dir() + '/libudev.sym'

install_headers('libudev.h')
libudev_h_path = '@0@/libudev.h'.format(meson.current_source_dir())

libudev_pc = configure_file(
        input : 'libudev.pc.in',
        output : 'libudev.pc',
        configuration : substs)
install_data(libudev_pc,
             install_dir : pkgconfiglibdir)
