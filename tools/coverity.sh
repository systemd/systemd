#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eux

COVERITY_SCAN_TOOL_BASE="/tmp/coverity-scan-analysis"
COVERITY_SCAN_PROJECT_NAME="systemd/systemd"

function coverity_install_script {
    local platform tool_url tool_archive

    platform=$(uname)
    tool_url="https://scan.coverity.com/download/${platform}"
    tool_archive="/tmp/cov-analysis-${platform}.tgz"

    set +x # this is supposed to hide COVERITY_SCAN_TOKEN
    echo -e "\033[33;1mDownloading Coverity Scan Analysis Tool...\033[0m"
    wget -nv -O "$tool_archive" "$tool_url" --post-data "project=$COVERITY_SCAN_PROJECT_NAME&token=${COVERITY_SCAN_TOKEN:?}"
    set -x

    mkdir -p "$COVERITY_SCAN_TOOL_BASE"
    pushd "$COVERITY_SCAN_TOOL_BASE"
    tar xzf "$tool_archive"
    popd
}

function run_coverity {
    local results_dir tool_dir results_archive sha response status_code

    results_dir="cov-int"
    tool_dir=$(find "$COVERITY_SCAN_TOOL_BASE" -type d -name 'cov-analysis*')
    results_archive="analysis-results.tgz"
    sha=$(git rev-parse --short HEAD)

    meson -Dman=false build
    COVERITY_UNSUPPORTED=1 "$tool_dir/bin/cov-build" --dir "$results_dir" sh -c "ninja -C ./build -v"
    "$tool_dir/bin/cov-import-scm" --dir "$results_dir" --scm git --log "$results_dir/scm_log.txt"

    tar czf "$results_archive" "$results_dir"

    set +x # this is supposed to hide COVERITY_SCAN_TOKEN
    echo -e "\033[33;1mUploading Coverity Scan Analysis results...\033[0m"
    response=$(curl \
               --silent --write-out "\n%{http_code}\n" \
               --form project="$COVERITY_SCAN_PROJECT_NAME" \
               --form token="${COVERITY_SCAN_TOKEN:?}" \
               --form email="${COVERITY_SCAN_NOTIFICATION_EMAIL:?}" \
               --form file="@$results_archive" \
               --form version="$sha" \
               --form description="Daily build" \
               https://scan.coverity.com/builds)
    printf "\033[33;1mThe response is\033[0m\n%s\n" "$response"
    status_code=$(echo "$response" | sed -n '$p')
    if [ "$status_code" != "200" ]; then
        echo -e "\033[33;1mCoverity Scan upload failed: $(echo "$response" | sed '$d').\033[0m"
        return 1
    fi
    set -x
}

coverity_install_script
run_coverity
