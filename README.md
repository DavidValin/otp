## One Time Pad "otp" command

This program takes stdin, xor's it with a key file and outputs to stdout.
When it finishes it writes a new file containing the part of the key file that was not used, ending with ".next".

When using one time pad algorithm, it is critical to remember to never reuse the part of the key that was used, that is why a new key file is created with the part that wasn't used. Once you use a key and the message has been sent to the recipient you should remove the old key file to avoid reusing the same region of the key. Always use the latest .next key file generated to encrypt next messages.

### Tutorial

[![YouTube](http://i.ytimg.com/vi/AE1kFnRsTuY/hqdefault.jpg)](https://www.youtube.com/watch?v=AE1kFnRsTuY)

### Install

**Build and test**
```
make
```

**Install**
```
sudo make install
```

musl supported, see Makefile

#### How to use

* Create a key file: `printf '%s' 'mysupersecretkey' > key.txt`
* Encrypt using key: `printf '%s' 'topsecretmsg' | otp key.txt > cipher.txt`
* Decrypt using key: `cat cipher.txt | otp key.txt > plain.txt`

#### Next key

Everytime you run the command it will create a new file with the same name as the key file ending with ".next".

#### True Random Number generator

Only a true random key makes this algorithm unbreakable. To generate a true random key consider [Infinite Noise TRNG](https://www.crowdsupply.com/leetronics/infinite-noise-trng). 

