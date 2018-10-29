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
        libudev-private.h
        libudev-queue.c
        libudev-util.c
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
