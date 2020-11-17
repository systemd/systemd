all setup run clean clean-again:
	@TEST_BASE_DIR=../ ./test.sh --$@

# finish option is used to run checks that can only be run outside of
# the test execution. Example case, honor first shutdown, proof is obtained
# from the console output as the image shuts down. This does not show up in
# the journal so the output from the do_test is captured in a file in /tmp.
# Without the use of finish the test will still pass because if it fails
# the test will loop and will be terminated via a command timeout.
# This just provides concrete confirmation.
finish:
	@TEST_BASE_DIR=../ ./fini.sh --$@

.PHONY: all setup run clean clean-again finish
