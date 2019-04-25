#!/bin/bash

set -e

# Download and extract coverity tool

# Environment check
[ -z "$COVERITY_SCAN_TOKEN" ] && echo 'ERROR: COVERITY_SCAN_TOKEN must be set' && exit 1

# Use default values if not set
PLATFORM=$(uname)

TOOL_BASE=${TOOL_BASE:="/tmp/coverity-scan-analysis"}
TOOL_ARCHIVE=${TOOL_ARCHIVE:="/tmp/cov-analysis-${PLATFORM}.tgz"}

TOOL_URL="https://scan.coverity.com/download/${PLATFORM}"

# Make sure wget is installed
sudo apt-get update && sudo apt-get -y install wget

# Get coverity tool
if [ ! -d $TOOL_BASE ]; then
    # Download Coverity Scan Analysis Tool
    if [ ! -e $TOOL_ARCHIVE ]; then
        echo -e "\033[33;1mDownloading Coverity Scan Analysis Tool...\033[0m"
        # According to https://www.ssllabs.com/ssltest/analyze.html?d=scan.coverity.com&latest,
        # the certificate chain is incomplete. Let's complete it manually by downloading the
        # missing piece (which is far from ideal but better than --no-check-certificate). This should
        # be removed once it ends up in /etc/ssl/certs/ca-certificates.crt officially.
        cp /etc/ssl/certs/ca-certificates.crt .
        wget -nv -O - https://entrust.com/root-certificates/entrust_l1k.cer | tee -a ./ca-certificates.crt
        wget --ca-certificate ./ca-certificates.crt -nv -O $TOOL_ARCHIVE $TOOL_URL --post-data "project=$COVERITY_SCAN_PROJECT_NAME&token=$COVERITY_SCAN_TOKEN"
    fi

    # Extract Coverity Scan Analysis Tool
    echo -e "\033[33;1mExtracting Coverity Scan Analysis Tool...\033[0m"
    mkdir -p $TOOL_BASE
    pushd $TOOL_BASE
    tar xzf $TOOL_ARCHIVE
    popd
fi

echo -e "\033[33;1mCoverity Scan Analysis Tool can be found at $TOOL_BASE ...\033[0m"
