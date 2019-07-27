#!/bin/bash

# The official unmodified version of the script can be found at
# https://scan.coverity.com/scripts/travisci_build_coverity_scan.sh

set -e

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
    AUTH=`echo $AUTH_RES | python -c "import sys, json; print(json.load(sys.stdin)['upload_permitted'])"`
    if [ "$AUTH" = "True" ]; then
        echo -e "\033[33;1mCoverity Scan analysis authorized per quota.\033[0m"
    else
        WHEN=`echo $AUTH_RES | python -c "import sys, json; print(json.load(sys.stdin)['next_upload_permitted_at'])"`
        echo -e "\033[33;1mCoverity Scan analysis NOT authorized until $WHEN.\033[0m"
        exit 1
    fi
fi

TOOL_DIR=`find $TOOL_BASE -type d -name 'cov-analysis*'`
export PATH="$TOOL_DIR/bin:$PATH"

# Disable CCACHE for cov-build to compilation units correctly
export CCACHE_DISABLE=1

# FUNCTION DEFINITIONS
# --------------------
_help()
{
    # displays help and exits
    cat <<-EOF
		USAGE: $0 [CMD] [OPTIONS]

		CMD
		  build   Issue Coverity build
		  upload  Upload coverity archive for analysis
              Note: By default, archive is created from default results directory.
                    To provide custom archive or results directory, see --result-dir
                    and --tar options below.

		OPTIONS
		  -h,--help     Display this menu and exits

		  Applicable to build command
		  ---------------------------
		  -o,--out-dir  Specify Coverity intermediate directory (defaults to 'cov-int')
		  -t,--tar      bool, archive the output to .tgz file (defaults to false)

		  Applicable to upload command
		  ----------------------------
		  -d, --result-dir   Specify result directory if different from default ('cov-int')
		  -t, --tar ARCHIVE  Use custom .tgz archive instead of intermediate directory or pre-archived .tgz
                         (by default 'analysis-result.tgz'
	EOF
    return;
}

_pack()
{
    RESULTS_ARCHIVE=${RESULTS_ARCHIVE:-'analysis-results.tgz'}

    echo -e "\033[33;1mTarring Coverity Scan Analysis results...\033[0m"
    tar czf $RESULTS_ARCHIVE $RESULTS_DIR
    SHA=`git rev-parse --short HEAD`

    PACKED=true
}


_build()
{
    echo -e "\033[33;1mRunning Coverity Scan Analysis Tool...\033[0m"
    local _cov_build_options=""
    #local _cov_build_options="--return-emit-failures 8 --parse-error-threshold 85"
    eval "${COVERITY_SCAN_BUILD_COMMAND_PREPEND}"
    COVERITY_UNSUPPORTED=1 cov-build --dir $RESULTS_DIR $_cov_build_options sh -c "$COVERITY_SCAN_BUILD_COMMAND"
    cov-import-scm --dir $RESULTS_DIR --scm git --log $RESULTS_DIR/scm_log.txt

    if [ $? != 0 ]; then
	echo -e "\033[33;1mCoverity Scan Build failed: $TEXT.\033[0m"
	return 1
    fi

    [ -z $TAR ] || [ $TAR = false ] && return 0

    if [ "$TAR" = true ]; then
	_pack
    fi
}


_upload()
{
    # pack results
    [ -z $PACKED ] || [ $PACKED = false ] && _pack

    # Upload results
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
    printf "\033[33;1mThe response is\033[0m\n%s\n" "$response"
    status_code=$(echo "$response" | sed -n '$p')
    # Coverity Scan used to respond with 201 on successfully receiving analysis results.
    # Now for some reason it sends 200 and may change back in the foreseeable future.
    # See https://github.com/pmem/pmdk/commit/7b103fd2dd54b2e5974f71fb65c81ab3713c12c5
    if [ "$status_code" != "200" ]; then
	TEXT=$(echo "$response" | sed '$d')
	echo -e "\033[33;1mCoverity Scan upload failed: $TEXT.\033[0m"
	exit 1
    fi

    echo -e "\n\033[33;1mCoverity Scan Analysis completed successfully.\033[0m"
    exit 0
}

# PARSE COMMAND LINE OPTIONS
# --------------------------

case $1 in
    -h|--help)
	_help
	exit 0
	;;
    build)
	CMD='build'
	TEMP=`getopt -o ho:t --long help,out-dir:,tar -n '$0' -- "$@"`
	_ec=$?
	[[ $_ec -gt 0 ]] && _help && exit $_ec
	shift
	;;
    upload)
	CMD='upload'
	TEMP=`getopt -o hd:t: --long help,result-dir:tar: -n '$0' -- "$@"`
	_ec=$?
	[[ $_ec -gt 0 ]] && _help && exit $_ec
	shift
	;;
    *)
	_help && exit 1 ;;
esac

RESULTS_DIR='cov-int'

eval set -- "$TEMP"
if [ $? != 0 ] ; then exit 1 ; fi

# extract options and their arguments into variables.
if [[ $CMD == 'build' ]]; then
    TAR=false
    while true ; do
	case $1 in
	    -h|--help)
		_help
		exit 0
		;;
	    -o|--out-dir)
		RESULTS_DIR="$2"
		shift 2
		;;
	    -t|--tar)
		TAR=true
		shift
		;;
	    --) _build; shift ; break ;;
	    *) echo "Internal error" ; _help && exit 6 ;;
	esac
    done

elif [[ $CMD == 'upload' ]]; then
    while true ; do
	case $1 in
	    -h|--help)
		_help
		exit 0
		;;
	    -d|--result-dir)
		CHANGE_DEFAULT_DIR=true
		RESULTS_DIR="$2"
		shift 2
		;;
	    -t|--tar)
		RESULTS_ARCHIVE="$2"
		[ -z $CHANGE_DEFAULT_DIR ] || [ $CHANGE_DEFAULT_DIR = false ] && PACKED=true
		shift 2
		;;
	    --) _upload; shift ; break ;;
	    *) echo "Internal error" ; _help && exit 6 ;;
	esac
    done

fi
