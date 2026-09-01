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
#   make clean      — remove build artifacts (probe binaries AND staged wrappers)
#   make clean-tests   — remove ONLY the probe binaries
#   make clean-staged  — remove ONLY this arch's staged wrapper binaries

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
TEST_CMA         = test/test_cma
TEST_IO_URING    = test/test_io_uring

TEST_BINS = $(TEST_SMOKE) $(TEST_PTRACE) $(TEST_PERS_QUERY) $(TEST_PERS_SWITCH) \
            $(TEST_AF_UNIX) $(TEST_CMA) $(TEST_IO_URING)

.PHONY: all install check check-tests clean clean-tests clean-staged

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

$(TEST_CMA): test/test_cma.c
	$(CC) $(CFLAGS_TEST) -o $@ $<

$(TEST_IO_URING): test/test_io_uring.c
	$(CC) $(CFLAGS_TEST) -o $@ $<

install: $(TARGET)
	install -m 0755 $(TARGET) $(HOME)/.local/bin/$(TARGET)

# The smoke suite's argument list lives HERE and nowhere else. build_and_test.sh
# calls `check-tests WRAPPER=<staged binary>` instead of repeating it — a second copy
# is a second thing to forget, and forgetting it once already blocked a Balfrin
# install (test_af_unix added to this file, not to that script).
#
# ... and until 2026-08-31 that claim was true of build_and_test.sh and FALSE of this
# file: $(TEST_BINS) above and the recipe below were two copies of one list, twelve lines
# apart. Adding a probe to TEST_BINS alone compiled it and never ran it — `summary: 0
# failed, 0 skipped`, exit 0, a new test born invisible (B6-6). The argv is now DERIVED
# from TEST_BINS, so there is one list (`P8`), and smoke.c's `argc != 8` arity check
# becomes a genuine tie: add a probe here and smoke refuses to run until it is taught
# about it, instead of silently ignoring it.
#
# Order matters — smoke.c reads its arguments positionally — so $(TEST_BINS) must stay in
# the order smoke.c's usage line states. filter-out drops the harness itself, which is
# argv[0] of the command rather than one of its arguments.
WRAPPER ?= ./$(TARGET)
PROBE_BINS = $(filter-out $(TEST_SMOKE),$(TEST_BINS))

check: $(TARGET) check-tests

check-tests: $(TEST_BINS)
	./$(TEST_SMOKE) $(WRAPPER) $(addprefix ./,$(PROBE_BINS))

# Removes ONLY the probe binaries, never $(TARGET): build_and_test.sh stages the freshly
# built wrapper into this directory and calls this on exit, so a `clean` there would
# delete the very thing it just produced.
clean-tests:
	rm -f $(TEST_BINS)

# The two names a build in this tree produces for THIS machine's arch. $(TARGET) is what
# `make install` reads; $(TARGET)-$(ARCH) is what install-husk.sh reads, and it is the ONLY
# one the installer looks at. Both are outputs of a build here, so a clean must remove both.
#
# Leaving the arch-tagged one behind is B6-7: `make clean` deleted $(TARGET) and spared
# $(TARGET)-$(ARCH), so a build that then FAILED its gates left the tree holding a stale
# arch-tagged binary from the previous build — and install-husk.sh's hash check answered
# "already up to date — nothing to do". Failed build → install → "success", while the
# cluster kept running the old wrapper. That is the identical failure build_and_test.sh's
# own closing message warns about (Balfrin, 2026-07-30), manufactured by the build.
#
# ARCH is only ever this machine's. A foreign-arch binary in this directory was scp'd here
# from the other cluster, not built here, and deleting someone else's artefact is not a
# clean's business.
#
# `override ARCH :=`, not `?=` and not a bare `:=`. `?=` yields to the environment, and ARCH
# is a very common exported variable — with it exported, `ARCH=aarch64 make clean-staged`
# on an x86_64 machine deleted the scp'd aarch64 binary and kept this machine's, the exact
# inverse of the sentence above. That was `RB-6`.
#
# A bare `:=` fixes only the reported case (`RB2-10`, measured). It beats a plain exported
# variable and it does NOT beat MAKEFLAGS or GNUMAKEFLAGS, which are also environment
# variables and whose contents make treats as command line — and `export MAKEFLAGS=-j8` in a
# login script is exactly the shape of thing that sets them:
#
#   ARCH=aarch64 make clean-staged            -> deletes this machine's       (`:=` holds)
#   MAKEFLAGS='ARCH=aarch64' make clean-staged -> deletes the FOREIGN one     (`:=` loses)
#   GNUMAKEFLAGS='-e' ARCH=aarch64 make ...    -> deletes the FOREIGN one     (`:=` loses)
#
# `override` wins over all three, including an explicit `make ARCH=... clean-staged`. That
# is a real loss — there is now no way to ask this target for another arch — and it is the
# right one: this target's whole contract is "remove what THIS machine staged", a foreign
# binary here was scp'd and cannot be rebuilt here, and `rm` is the wrong tool for wanting
# it gone. The comment used to claim the command line "still wins, which is the right
# split"; it no longer does, and saying so is the point (`P12`).
override ARCH := $(shell uname -m)
STAGED_BINS = $(TARGET) $(TARGET)-$(ARCH)

clean-staged:
	rm -f $(STAGED_BINS)

clean: clean-tests clean-staged
