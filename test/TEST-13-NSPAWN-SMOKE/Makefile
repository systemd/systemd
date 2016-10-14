all: has-overflow
	@make -s --no-print-directory -C ../.. all
	@basedir=../.. TEST_BASE_DIR=../ ./test.sh --all
setup: has-overflow
	@make --no-print-directory -C ../.. all
	@basedir=../.. TEST_BASE_DIR=../ ./test.sh --setup
clean:
	@basedir=../.. TEST_BASE_DIR=../ ./test.sh --clean
	@rm -f has-overflow
run:
	@basedir=../.. TEST_BASE_DIR=../ ./test.sh --run
