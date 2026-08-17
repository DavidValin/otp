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
		$(CC) $(BUILD_FLAGS) /Fe:$(BIN) src/otp.c src/keychain.c src/commit.c || exit 1; \
	else \
		$(CC) $(BUILD_FLAGS) -o $(BIN) src/otp.c src/keychain.c src/commit.c || exit 1; \
	fi
	@echo " - Built!"
	@echo " - Testing..."
	@bash test/otp.test.sh
	@bash test/keychain.test.sh
	@bash test/commit.test.sh
	@bash test/lock.test.sh
	@bash test/metadata.test.sh
	@bash test/confirm.test.sh
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
	@musl-gcc -static -D_FILE_OFFSET_BITS=64 -o $(BIN) src/otp.c src/keychain.c src/commit.c
	@echo " - Built!"
	@echo " - Testing..."
	@bash test/otp.test.sh
	@bash test/keychain.test.sh
	@bash test/commit.test.sh
	@bash test/lock.test.sh
	@bash test/metadata.test.sh
	@bash test/confirm.test.sh
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
	@x86_64-w64-mingw32-gcc -Wall -Wextra -O2 -o bin/otp.exe src/otp.c src/keychain.c src/commit.c
	@echo " - Built bin/otp.exe!"
	@echo

# Cross-compile Linux ARM binaries with the GNU cross toolchains
# (gcc-aarch64-linux-gnu / gcc-arm-linux-gnueabihf). The test suite cannot
# run here (the binary targets another architecture); on an ARM host,
# plain `make build` compiles natively and runs the full suite instead.
# _FILE_OFFSET_BITS=64 matters most on arm32, where off_t is 32-bit by
# default and keys over 2GB would fail without it.
arm64:
	@echo
	@echo " - Cross-compiling Linux arm64 binary..."
	@mkdir -p bin
	@aarch64-linux-gnu-gcc -Wall -Wextra -O2 -D_FILE_OFFSET_BITS=64 -o $(BIN) src/otp.c src/keychain.c src/commit.c
	@echo " - Built bin/otp (arm64)!"
	@echo

arm32:
	@echo
	@echo " - Cross-compiling Linux arm32 (hard-float) binary..."
	@mkdir -p bin
	@arm-linux-gnueabihf-gcc -Wall -Wextra -O2 -D_FILE_OFFSET_BITS=64 -o $(BIN) src/otp.c src/keychain.c src/commit.c
	@echo " - Built bin/otp (arm32)!"
	@echo

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
