BUILD_DIR=$(shell ../../tools/find-build-dir.sh)

all setup run:
	@basedir=../.. TEST_BASE_DIR=../ BUILD_DIR=$(BUILD_DIR) ./test.sh --$@
clean:
	@basedir=../.. TEST_BASE_DIR=../ ./test.sh --clean
	@rm -f has-overflow
