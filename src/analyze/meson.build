# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_analyze_sources = files(
        'analyze-blame.c',
        'analyze-calendar.c',
        'analyze-capability.c',
        'analyze-cat-config.c',
        'analyze-compare-versions.c',
        'analyze-condition.c',
        'analyze-critical-chain.c',
        'analyze-dot.c',
        'analyze-dump.c',
        'analyze-exit-status.c',
        'analyze-fdstore.c',
        'analyze-filesystems.c',
        'analyze-image-policy.c',
        'analyze-inspect-elf.c',
        'analyze-log-control.c',
        'analyze-malloc.c',
        'analyze-plot.c',
        'analyze-security.c',
        'analyze-service-watchdogs.c',
        'analyze-syscall-filter.c',
        'analyze-time.c',
        'analyze-time-data.c',
        'analyze-timespan.c',
        'analyze-timestamp.c',
        'analyze-unit-files.c',
        'analyze-unit-paths.c',
        'analyze-verify.c',
        'analyze-verify-util.c',
        'analyze.c',
)

tests += [
        {
                'sources' : files(
                        'test-verify.c',
                        'analyze-verify-util.c',
                ),
                'base' : test_core_base,
        },
]
