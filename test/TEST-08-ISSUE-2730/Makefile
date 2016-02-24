all:
	@make -s --no-print-directory -C ../.. all
	@basedir=../.. TEST_BASE_DIR=../ ./test.sh --all
setup:
	@make --no-print-directory -C ../.. all
	@basedir=../.. TEST_BASE_DIR=../ ./test.sh --setup
clean:
	@basedir=../.. TEST_BASE_DIR=../ ./test.sh --clean
run:
	@basedir=../.. TEST_BASE_DIR=../ ./test.sh --run
