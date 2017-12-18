#!/bin/sh

# Declare build command
COVERITY_SCAN_BUILD_COMMAND="ninja -C cov-build"

# Environment check
# Use default values if not set
SCAN_URL=${SCAN_URL:="https://scan.coverity.com"}
TOOL_BASE=${TOOL_BASE:="/tmp/coverity-scan-analysis"}
UPLOAD_URL=${UPLOAD_URL:="https://scan.coverity.com/builds"}

# These must be set by environment
echo -e "\033[33;1mNote: COVERITY_SCAN_PROJECT_NAME and COVERITY_SCAN_TOKEN are available on Project Settings page on scan.coverity.com\033[0m"
[ -z "$COVERITY_SCAN_PROJECT_NAME" ] && echo "ERROR: COVERITY_SCAN_PROJECT_NAME must be set" && exit 1
[ -z "$COVERITY_SCAN_NOTIFICATION_EMAIL" ] && echo "ERROR: COVERITY_SCAN_NOTIFICATION_EMAIL must be set" && exit 1
[ -z "$COVERITY_SCAN_BRANCH_PATTERN" ] && echo "ERROR: COVERITY_SCAN_BRANCH_PATTERN must be set" && exit 1
[ -z "$COVERITY_SCAN_BUILD_COMMAND" ] && echo "ERROR: COVERITY_SCAN_BUILD_COMMAND must be set" && exit 1
[ -z "$COVERITY_SCAN_TOKEN" ] && echo "ERROR: COVERITY_SCAN_TOKEN must be set" && exit 1

# Do not run on pull requests
if [ "${TRAVIS_PULL_REQUEST}" = "true" ]; then
  echo -e "\033[33;1mINFO: Skipping Coverity Analysis: branch is a pull request.\033[0m"
  exit 0
fi

# Verify this branch should run
if [[ "${TRAVIS_BRANCH^^}" =~ "${COVERITY_SCAN_BRANCH_PATTERN^^}" ]]; then
  echo -e "\033[33;1mCoverity Scan configured to run on branch ${TRAVIS_BRANCH}\033[0m"
else
  echo -e "\033[33;1mCoverity Scan NOT configured to run on branch ${TRAVIS_BRANCH}\033[0m"
  exit 1
fi

# Verify upload is permitted
AUTH_RES=`curl -s --form project="$COVERITY_SCAN_PROJECT_NAME" --form token="$COVERITY_SCAN_TOKEN" $SCAN_URL/api/upload_permitted`
if [ "$AUTH_RES" = "Access denied" ]; then
  echo -e "\033[33;1mCoverity Scan API access denied. Check COVERITY_SCAN_PROJECT_NAME and COVERITY_SCAN_TOKEN.\033[0m"
  exit 1
else
	AUTH=`echo $AUTH_RES | python -c "import sys, json; print json.load(sys.stdin)['upload_permitted']"`
  if [ "$AUTH" = "True" ]; then
    echo -e "\033[33;1mCoverity Scan analysis authorized per quota.\033[0m"
  else
	  WHEN=`echo $AUTH_RES | python -c "import sys; json; print json.load(sys.stdin)['next_upload_permitted_at']"`
    echo -e "\033[33;1mCoverity Scan analysis NOT authorized until $WHEN.\033[0m"
    exit 0
  fi
fi

TOOL_DIR=`find $TOOL_BASE -type d -name 'cov-analysis*'`
export PATH="$TOOL_DIR/bin:$PATH"

# Disable CCACHE for cov-build to compilation units correctly
export CCACHE_DISABLE=1

# Build
echo -e "\033[33;1mRunning Coverity Scan Analysis Tool...\033[0m"
COV_BUILD_OPTIONS=""
#COV_BUILD_OPTIONS="--return-emit-failures 8 --parse-error-threshold 85"
RESULTS_DIR="cov-int"
eval "${COVERITY_SCAN_BUILD_COMMAND_PREPEND}"
COVERITY_UNSUPPORTED=1 cov-build --dir $RESULTS_DIR $COV_BUILD_OPTIONS sh -c "$COVERITY_SCAN_BUILD_COMMAND"
cov-import-scm --dir $RESULTS_DIR --scm git --log $RESULTS_DIR/scm_log.txt

if [ $? != 0 ]; then
  echo -e "\033[33;1mCoverity Scan Build failed: $TEXT.\033[0m"
	exit 1
fi

# Upload results
echo -e "\033[33;1mTarring Coverity Scan Analysis results...\033[0m"
RESULTS_ARCHIVE=analysis-results.tgz
tar czf $RESULTS_ARCHIVE $RESULTS_DIR
SHA=`git rev-parse --short HEAD`

echo -e "\033[33;1mUploading Coverity Scan Analysis results...\033[0m"
response=$(curl \
  --silent --write-out "\n%{http_code}\n" \
  --form project=$COVERITY_SCAN_PROJECT_NAME \
  --form token=$COVERITY_SCAN_TOKEN \
  --form email=$COVERITY_SCAN_NOTIFICATION_EMAIL \
  --form file=@$RESULTS_ARCHIVE \
  --form version=$SHA \
  --form description="Travis CI build" \
  $UPLOAD_URL)
status_code=$(echo "$response" | sed -n '$p')
if [ "$status_code" != "201" ]; then
  TEXT=$(echo "$response" | sed '$d')
  echo -e "\033[33;1mCoverity Scan upload failed: $TEXT.\033[0m"
  exit 1
fi

echo -e "\n\033[33;1mCoverity Scan Analysis completed succesfully.\033[0m"
exit 0
