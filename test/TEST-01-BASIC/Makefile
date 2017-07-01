all:
	@ninja -C "$$ABS_BUILD_DIR" all
	@basedir=../.. TEST_BASE_DIR=../ ./test.sh --all
setup:
	@ninja -C "$$ABS_BUILD_DIR" all
	@basedir=../.. TEST_BASE_DIR=../ ./test.sh --setup
clean:
	@basedir=../.. TEST_BASE_DIR=../ ./test.sh --clean
run:
	@basedir=../.. TEST_BASE_DIR=../ ./test.sh --run
