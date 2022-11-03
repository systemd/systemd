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
libudev_sym_path = meson.current_source_dir() / 'libudev.sym'

install_headers('libudev.h')
libudev_h_path = meson.current_source_dir() / 'libudev.h'

libudev_basic = static_library(
        'udev-basic',
        libudev_sources,
        include_directories : includes,
        c_args : ['-fvisibility=default'],
        build_by_default : false)

static_libudev = get_option('static-libudev')
static_libudev_pic = static_libudev == 'true' or static_libudev == 'pic'

libudev_pc = custom_target(
        'libudev.pc',
        input : 'libudev.pc.in',
        output : 'libudev.pc',
        command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
        install : pkgconfiglibdir != 'no',
        install_tag : 'devel',
        install_dir : pkgconfiglibdir)

############################################################

tests += [
        [files('test-libudev.c'),
         [libshared,
          libudev_basic]],
]
