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
  BUILD_FLAGS := -O2 -Wall
endif

BIN := bin/otp$(BIN_EXT)

build:
	@echo
	@echo " - Building..."
	@mkdir -p bin
	@if [ "$(OS)" = "Windows_NT" ]; then \
		$(CC) $(BUILD_FLAGS) /Fe:$(BIN) src/otp.c || exit 1; \
	else \
		$(CC) $(BUILD_FLAGS) -o $(BIN) src/otp.c || exit 1; \
	fi
	@echo " - Built!"
	@echo " - Testing..."
	@sh test/otp.test.sh
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

# Static musl build only for Unix-like systems
ifneq ($(OS),Windows_NT)
musl:
	@echo
	@echo " - Building musl static binary..."
	@mkdir -p bin
	@musl-gcc -static -o $(BIN) src/otp.c
	@echo " - Built!"
	@echo " - Testing..."
	@sh test/otp.test.sh
	@echo " - Tested!"
	@echo

install-musl:
	@echo
	@echo " - Installing musl binary..."
	@mv ./bin/otp /usr/local/bin/otp-musl
	@echo " - Installed! You can use \"otp-musl\" now"
	@echo
endif
