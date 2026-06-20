#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Generate the SPI annual report blurb.
#
# Usage: tools/spi-report.sh [YEAR]
#
# YEAR defaults to the previous calendar year.

set -euo pipefail

year="${1:-$(($(date +%Y) - 1))}"
prev_year=$((year - 1))

range_start="${year}-01-01T00:00:00"
range_end="$((year + 1))-01-01T00:00:00"
prev_range_start="${prev_year}-01-01T00:00:00"
prev_range_end="${year}-01-01T00:00:00"

tags="$(git for-each-ref --format='%(creatordate:format:%Y) %(refname:short)' 'refs/tags/v[0-9]*')"

major_releases="$(grep -cE "^${year} v[0-9]+\$" <<<"$tags" || true)"
point_releases="$(grep -cE "^${year} v[0-9]+\.[0-9]+\$" <<<"$tags" || true)"

commits="$(git rev-list --count --no-merges --since="$range_start" --until="$range_end" HEAD)"
prev_commits="$(git rev-list --count --no-merges --since="$prev_range_start" --until="$prev_range_end" HEAD)"

contributors="$(git shortlog -s --group=author --group=trailer:Co-authored-by \
    --since="$range_start" --until="$range_end" HEAD |
    sed -e '/Weblate/ d' -e '/dependabot\[bot\]/ d' | wc -l)"

if [ "$commits" -ge "$prev_commits" ]; then
    trend="up from"
else
    trend="down from"
fi

cat <<EOF
systemd is a suite of basic building blocks for a Linux system. It
provides a system and service manager that runs as PID 1 and starts
the rest of the system.

In ${year} we published ${major_releases} major releases of systemd and ${point_releases} point
releases with bug fixes. We merged ${commits} commits (${trend} ${prev_commits} in ${prev_year})
from a total of ${contributors} contributors.
We organized the Image-Based Linux Summit
(<placeholder for link to minutes>)
and we participated in All Systems Go!
(https://cfp.all-systems-go.io/all-systems-go-${year}/schedule/) in Berlin.

We continue to hold a biweekly maintainers meeting and the project is
maintaining a steady pace of development.
EOF
