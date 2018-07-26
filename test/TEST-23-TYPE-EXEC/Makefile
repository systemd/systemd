BUILD_DIR=$(shell ../../tools/find-build-dir.sh)

all setup clean run:
	@basedir=../.. TEST_BASE_DIR=../ BUILD_DIR=$(BUILD_DIR) ./test.sh --$@
