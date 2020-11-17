BUILD_DIR=$(shell ../../tools/find-build-dir.sh)

all setup run clean clean-again:
	@TEST_BASE_DIR=../ BUILD_DIR=$(BUILD_DIR) ./test.sh --$@

.PHONY: all setup run clean clean-again
