# Detect operating system and set compiler flags
OS := $(shell uname -s 2>/dev/null)
ifeq ($(OS),)
  OS := Windows_NT
endif

# Default compiler and binary extension
ifeq ($(OS),Windows_NT)
  CC := cl
  BIN_EXT := .exe
  BUILD_FLAGS := /O2 /Wall
else
  CC := gcc
  BIN_EXT :=
  # Enable Large File Support (LFS) for files >2GB on 32-bit systems
  BUILD_FLAGS := -O2 -Wall -D_FILE_OFFSET_BITS=64
endif

BIN := bin/otp$(BIN_EXT)

build:
	@echo
	@echo " - Building..."
	@mkdir -p bin
	@if [ "$(OS)" = "Windows_NT" ]; then \
		$(CC) $(BUILD_FLAGS) /Fe:$(BIN) src/cli.c src/keychain.c src/cipher.c src/commit.c || exit 1; \
	else \
		$(CC) $(BUILD_FLAGS) -o $(BIN) src/cli.c src/keychain.c src/cipher.c src/commit.c || exit 1; \
	fi
	@echo " - Built!"
	@echo " - Testing..."
	@bash test/otp.test.sh
	@bash test/keychain.test.sh
	@bash test/commit.test.sh
	@bash test/lock.test.sh
	@bash test/metadata.test.sh
	@bash test/confirm.test.sh
	@bash test/lastcopy.test.sh
	@bash test/truncate.test.sh
	@echo " - Tested!"
	@echo

install:
	@echo
	@echo " - Installing..."
	@if [ "$(OS)" = "Windows_NT" ]; then \
		mv ./bin/otp.exe /usr/local/bin/otp.exe; \
	else \
		mv ./bin/otp /usr/local/bin/otp; \
	fi
	@echo " - Installed! You can use \"otp\" now"
	@echo
	@mkdir -p /usr/local/share/man/man1
	@cp otp.1 /usr/local/share/man/man1/otp.1
	@echo " - Man page installed to /usr/local/share/man/man1/otp.1"

# Static musl build only for Unix-like systems
ifneq ($(OS),Windows_NT)
musl:
	@echo
	@echo " - Building musl static binary..."
	@mkdir -p bin
	@musl-gcc -static -D_FILE_OFFSET_BITS=64 -o $(BIN) src/cli.c src/keychain.c src/cipher.c src/commit.c
	@echo " - Built!"
	@echo " - Testing..."
	@bash test/otp.test.sh
	@bash test/keychain.test.sh
	@bash test/commit.test.sh
	@bash test/lock.test.sh
	@bash test/metadata.test.sh
	@bash test/confirm.test.sh
	@bash test/lastcopy.test.sh
	@bash test/truncate.test.sh
	@echo " - Tested!"
	@echo

# Cross-compile a Windows binary with MinGW-w64 (the native Windows build
# above uses cl). Also serves as the Windows-compatibility check on a
# POSIX machine: it compiles every Windows branch against the real Win32
# and CRT headers with all warnings on.
mingw:
	@echo
	@echo " - Cross-compiling Windows binary with MinGW-w64..."
	@mkdir -p bin
	@x86_64-w64-mingw32-gcc -Wall -Wextra -O2 -o bin/otp.exe src/cli.c src/keychain.c src/cipher.c src/commit.c
	@echo " - Built bin/otp.exe!"
	@echo

# Cross-compile Linux binaries for foreign architectures with the GNU
# cross toolchains (gcc-aarch64-linux-gnu / gcc-arm-linux-gnueabihf /
# gcc-riscv64-linux-gnu). A cross-built binary cannot be executed by the
# build machine directly, so these targets build only; the test-arm32 and
# test-riscv64 targets below run the full suite against them under
# qemu-user emulation (arm64 is instead tested natively, both in CI and
# by `make build` on any arm64 host). arm32 and riscv64 are built static:
# the program uses no NSS/dlopen functionality, so static (glibc) linking
# is safe, and it makes the binary run on any distribution - and under
# qemu with no target sysroot. _FILE_OFFSET_BITS=64 matters most on
# arm32, where off_t is 32-bit by default and keys over 2GB would fail
# without it.
arm64:
	@echo
	@echo " - Cross-compiling Linux arm64 binary..."
	@mkdir -p bin
	@aarch64-linux-gnu-gcc -Wall -Wextra -O2 -D_FILE_OFFSET_BITS=64 -o $(BIN) src/cli.c src/keychain.c src/cipher.c src/commit.c
	@echo " - Built bin/otp (arm64)!"
	@echo

arm32:
	@echo
	@echo " - Cross-compiling Linux arm32 (hard-float) static binary..."
	@mkdir -p bin
	@arm-linux-gnueabihf-gcc -static -Wall -Wextra -O2 -D_FILE_OFFSET_BITS=64 -o $(BIN) src/cli.c src/keychain.c src/cipher.c src/commit.c
	@echo " - Built bin/otp (arm32)!"
	@echo

riscv64:
	@echo
	@echo " - Cross-compiling Linux riscv64 static binary..."
	@mkdir -p bin
	@riscv64-linux-gnu-gcc -static -Wall -Wextra -O2 -D_FILE_OFFSET_BITS=64 -o $(BIN) src/cli.c src/keychain.c src/cipher.c src/commit.c
	@echo " - Built bin/otp (riscv64)!"
	@echo

# Run the full test suite against a cross-built binary under qemu
# user-mode emulation - the same coverage CI has, runnable locally.
# Needs the matching qemu binary on PATH (package: qemu-user or
# qemu-user-static). bin/otp is temporarily replaced by a wrapper that
# routes every ./bin/otp invocation through qemu, and the real binary is
# put back when the suite finishes, pass or fail.
test-arm32: arm32
	@echo " - Testing arm32 binary under qemu..."
	@QEMU=$$(command -v qemu-arm || command -v qemu-arm-static); \
	[ -n "$$QEMU" ] || { echo "Error: qemu-arm not found (install qemu-user or qemu-user-static)"; exit 1; }; \
	mv bin/otp bin/otp.target; \
	printf '#!/bin/sh\nexec %s "$$(dirname "$$0")/otp.target" "$$@"\n' "$$QEMU" > bin/otp; \
	chmod +x bin/otp; \
	rc=0; \
	for t in otp keychain commit lock metadata confirm truncate; do \
	  bash test/$$t.test.sh || { rc=1; break; }; \
	done; \
	mv bin/otp.target bin/otp; \
	[ $$rc -eq 0 ] && echo " - Tested!"; exit $$rc

test-riscv64: riscv64
	@echo " - Testing riscv64 binary under qemu..."
	@QEMU=$$(command -v qemu-riscv64 || command -v qemu-riscv64-static); \
	[ -n "$$QEMU" ] || { echo "Error: qemu-riscv64 not found (install qemu-user or qemu-user-static)"; exit 1; }; \
	mv bin/otp bin/otp.target; \
	printf '#!/bin/sh\nexec %s "$$(dirname "$$0")/otp.target" "$$@"\n' "$$QEMU" > bin/otp; \
	chmod +x bin/otp; \
	rc=0; \
	for t in otp keychain commit lock metadata confirm truncate; do \
	  bash test/$$t.test.sh || { rc=1; break; }; \
	done; \
	mv bin/otp.target bin/otp; \
	[ $$rc -eq 0 ] && echo " - Tested!"; exit $$rc

install-musl:
	@echo
	@echo " - Installing musl binary..."
	@mv ./bin/otp /usr/local/bin/otp-musl
	@echo " - Installed! You can use \"otp-musl\" now"
	@echo
	@mkdir -p /usr/local/share/man/man1
	@cp otp.1 /usr/local/share/man/man1/otp.1
	@echo " - Man page installed to /usr/local/share/man/man1/otp.1"
	@echo
	@echo
endif
