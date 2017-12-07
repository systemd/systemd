BUILD_DIR=$(exec ../../tools/find-build-dir.sh)

all setup clean run:
	@basedir=../.. TEST_BASE_DIR=../ BUILD_DIR=$(BUILD_DIR) ./test.sh --$@
