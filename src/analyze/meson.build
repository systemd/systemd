# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_analyze_sources = files('''
        analyze-blame.c
        analyze-blame.h
        analyze-calendar.c
        analyze-calendar.h
        analyze-capability.c
        analyze-capability.h
        analyze-cat-config.c
        analyze-cat-config.h
        analyze-condition.c
        analyze-condition.h
        analyze-dot.c
        analyze-dot.h
        analyze-dump.c
        analyze-dump.h
        analyze-elf.c
        analyze-elf.h
        analyze-exit-status.c
        analyze-exit-status.h
        analyze-filesystems.c
        analyze-filesystems.h
        analyze-plot.c
        analyze-plot.h
        analyze-security.c
        analyze-security.h
        analyze-service-watchdogs.c
        analyze-service-watchdogs.h
        analyze-syscall-filter.c
        analyze-syscall-filter.h
        analyze-time-data.c
        analyze-time-data.h
        analyze-timespan.c
        analyze-timespan.h
        analyze-timestamp.c
        analyze-timestamp.h
        analyze-verify.c
        analyze-verify.h
        analyze.c
'''.split())

tests += [
        [files('test-verify.c',
               'analyze-verify.c',
               'analyze-verify.h'),
         [libcore,
          libshared],
         [],
         core_includes],
]
