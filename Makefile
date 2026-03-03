build:
	@echo
	@echo " - Building..."
	@mkdir -p bin
	@gcc -o bin/otp src/otp.c
	@echo " - Built!"
	@echo " - Testing..."
	@sh test/otp.test.sh
	@echo " - Tested!"
	@echo

install:
	@echo
	@echo " - Installing..."
	@mv ./bin/otp /usr/local/bin/otp
	@echo " - Installed! You can use \"otp\" now"
	@echo

musl:
	@echo
	@echo " - Building musl static binary..."
	@mkdir -p bin
	@musl-gcc -static -o bin/otp src/otp.c
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
