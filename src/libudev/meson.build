# SPDX-License-Identifier: LGPL-2.1-or-later

libudev_sources = files(
        'libudev-device.c',
        'libudev-device-internal.h',
        'libudev-enumerate.c',
        'libudev-hwdb.c',
        'libudev-list.c',
        'libudev-list-internal.h',
        'libudev-monitor.c',
        'libudev-queue.c',
        'libudev-util.c',
        'libudev-util.h',
        'libudev.c',
        'libudev.h')

############################################################

libudev_includes = [includes, include_directories('.')]

libudev_sym = files('libudev.sym')
libudev_sym_path = join_paths(meson.current_source_dir(), 'libudev.sym')

install_headers('libudev.h')
libudev_h_path = join_paths(meson.current_source_dir(), 'libudev.h')

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

configure_file(
        input : 'libudev.pc.in',
        output : 'libudev.pc',
        configuration : substs,
        install_dir : pkgconfiglibdir == 'no' ? '' : pkgconfiglibdir)

############################################################

tests += [
        [['src/libudev/test-libudev.c'],
         [libshared,
          libudev_static]],
]
