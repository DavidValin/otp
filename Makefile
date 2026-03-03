build:
	@echo " - Building..."
	@mkdir -p bin
	@gcc -o bin/otp src/otp.c
	@echo " - Built!"
	@echo " - Testing..."
	@sh test/otp.test.sh
	@echo " - Tested!"

install:
	@echo " - Installing..."
	@mv ./bin/otp /usr/local/bin/otp
	@echo " - Installed! You can use \"otp\" now"

musl:
	@echo " - Building musl static binary..."
	@mkdir -p bin
	@musl-gcc -static -o bin/otp src/otp.c
	@echo " - Built!"
	@echo " - Testing..."
	@sh test/otp.test.sh
	@echo " - Tested!"

install-musl:
	@echo " - Installing musl binary..."
	@mv ./bin/otp /usr/local/bin/otp-musl
	@echo " - Installed! You can use \"otp-musl\" now"