# SPDX-License-Identifier: LGPL-2.1+

systemd_rdtd_sources = files('''
        rdtd.c
        rdtd.h
'''.split())

rdtd_gperf_c = custom_target(
        'rdtd_gperf.c',
        input : 'rdtd-gperf.gperf',
        output : 'rdtd-gperf.c',
        command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

librdtd_core_sources = files('''
        rdtd-core.c
        rdtd-group.h
        rdtd-group.c
        rdtd-info.h
        rdtd-resctrl.h
        rdtd-resctrl.c
'''.split())

librdtd_core_sources += [rdtd_gperf_c]

librdtd_core = static_library(
        'rdtd-core',
        librdtd_core_sources,
        include_directories : includes,
        dependencies : [])

if conf.get('ENABLE_RDTD') == 1
        rdtd_conf = configure_file(
                input : 'rdtd.conf.in',
                output : 'rdtd.conf',
                configuration : substs)
        install_data(rdtd_conf,
                     install_dir : pkgsysconfdir)
endif
