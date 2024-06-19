## One Time Pad "otp" command

This program takes stdin, xor's it with a key file and outputs to stdout.
When it finishes it writes a new file containing the part of the key file that was not used, ending with ".next". When using one time pad, remember to never reuse the keys, that is why a new key file is created with the part that wasn't used. You should always remove the key that you have used once.

### Tutorial

[![YouTube](http://i.ytimg.com/vi/AE1kFnRsTuY/hqdefault.jpg)](https://www.youtube.com/watch?v=AE1kFnRsTuY)

### Install

* Build and test: `make`
* Install: `sudo make install`

#### How to use it

* Create a key file: `echo -n "mysupersecretkey" > key.txt`
* Encrypt using key: `echo -n "hello" | otp key.txt > cipher.txt`
* Decrypt using key: `cat cipher.txt | otp key.txt > plain.txt`

#### Next key

Everytime you run the command it will create a new file with the same name as the key file ending with ".next". You should never reuse keys once they are used (one time pad algorithm requirements), therefore you should remove the original key file and use the new key file generated next time.

