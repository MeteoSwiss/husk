# Makefile for seccomp-wrapper
#
# Requirements:
#   libseccomp — either system-installed (apt install libseccomp-dev) or
#                built from source into ~/.local (see README.md)
#
# Targets:
#   make            — build the wrapper binary
#   make install    — copy to ~/.local/bin
#   make check      — compile and run the smoke tests
#   make clean      — remove build artifacts

CC          = gcc
CFLAGS      = -static -O2 -Wall -Wextra -Wpedantic -std=c11 \
              -I$(HOME)/.local/include
LDFLAGS     = -L$(HOME)/.local/lib -lseccomp
CFLAGS_TEST = -O2 -Wall -Wextra -Wpedantic -std=c11

TARGET           = seccomp-wrapper
SRC              = src/seccomp_wrapper.c
TEST_SMOKE       = test/smoke
TEST_PTRACE      = test/test_ptrace
TEST_PERS_QUERY  = test/test_personality_query
TEST_PERS_SWITCH = test/test_personality_switch
TEST_AF_UNIX     = test/test_af_unix

.PHONY: all install check check-tests clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(TEST_SMOKE): test/smoke.c
	$(CC) $(CFLAGS_TEST) -o $@ $<

$(TEST_PTRACE): test/test_ptrace.c
	$(CC) $(CFLAGS_TEST) -o $@ $<

$(TEST_PERS_QUERY): test/test_personality_query.c
	$(CC) $(CFLAGS_TEST) -o $@ $<

$(TEST_AF_UNIX): test/test_af_unix.c
	$(CC) $(CFLAGS_TEST) -o $@ $<

$(TEST_PERS_SWITCH): test/test_personality_switch.c
	$(CC) $(CFLAGS_TEST) -o $@ $<

install: $(TARGET)
	install -m 0755 $(TARGET) $(HOME)/.local/bin/$(TARGET)

# The smoke suite's argument list lives HERE and nowhere else. build_and_test.sh
# calls `check-tests WRAPPER=<staged binary>` instead of repeating it — a second copy
# is a second thing to forget, and forgetting it once already blocked a Balfrin
# install (test_af_unix added to this file, not to that script).
WRAPPER ?= ./$(TARGET)

check: $(TARGET) check-tests

check-tests: $(TEST_SMOKE) $(TEST_PTRACE) $(TEST_PERS_QUERY) $(TEST_PERS_SWITCH) $(TEST_AF_UNIX)
	./$(TEST_SMOKE) $(WRAPPER) ./$(TEST_PTRACE) ./$(TEST_PERS_QUERY) ./$(TEST_PERS_SWITCH) ./$(TEST_AF_UNIX)

clean:
	rm -f $(TARGET) $(TEST_SMOKE) $(TEST_PTRACE) $(TEST_PERS_QUERY) $(TEST_PERS_SWITCH) \
	      $(TEST_AF_UNIX)
