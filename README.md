## One Time Pad "otp" command

This program takes stdin, xor's it with a key file and outputs to stdout.
When it finishes it writes a new file containing the part of the key file that was not used, ending with ".next".

When using one time pad algorithm, it is critical to remember to never reuse the part of the key that was used, that is why a new key file is created with the part that wasn't used. Once you use a key and the message has been sent to the recipient you should remove the old key file to avoid reusing the same region of the key. Always use the latest .next key file generated to encrypt next messages.

### Tutorial

[![YouTube](http://i.ytimg.com/vi/AE1kFnRsTuY/hqdefault.jpg)](https://www.youtube.com/watch?v=AE1kFnRsTuY)

## Installation

```
make
sudo make install
```

* musl supported, see Makefile

## New key pair generation

Use the `-nk` or `--new-key-pair` flag to generate a new key pair from a source of randomness. This is useful when you need to create two complementary key files that will be split between parties. Each party receives 2 keys, an encryption key (used for sending messages) and a decryption key (used to receive messages) ensuring that what a party encrypts the other can decrypt and vice versa.

Example (generates 2 key pairs of 1MB length, one pair for each party)
```
cat /dev/urandom | otp --new-key-pair 1 alice bob
```

key pair for alice:
```
encryption_bob.txt
decryption_bob.txt
```

key pair for bob:
```
encryption_alice.txt
decryption_alice.txt
```

#### True Random key generator

Only a true random key makes this algorithm unbreakable.
To generate a true random key consider [Infinite Noise TRNG](https://www.crowdsupply.com/leetronics/infinite-noise-trng).


## Keychain Management Commands

List all keychain commands:
```bash
otp --help
```

Common operations:

- **Add contact without keys:** `otp --add-contact <name>` or `otp -ac <name>`
- **Add contact with keys:** `otp --add-contact <name> <enc_key> <dec_key>`
- **List contacts:** `otp --list-contacts` or `otp -lc`
- **Show contact details:** `otp --show-contact <name>` or `otp -sc <name>`
- **Remove contact:** `otp --remove-contact <name>` or `otp -rc <name>`
- **Check if contact exists:** `otp --has-contact <name>` or `otp -hc <name>`

#### Keychain Features

- **Streaming architecture:** Keys stored in `.keychain/` directory, read in 4MB chunks - supports keys up to 1TB without loading into RAM
- **Automatic key management:** Keys are consumed automatically; no manual .next file handling
- **Metadata tracking:** Sequence numbers, offsets, and timestamps tracked for each contact in `keychain.txt`
- **Perfect forward secrecy:** Key consumption tracked via offsets; past messages can't be decrypted if offset information is lost
- **Binary safe:** Handles binary cipher text correctly
- **Security:** Keys are masked (displayed as *******) when viewing contact info
- **File structure:**
  - `keychain.txt` - Contact metadata (names, paths, offsets, sequences)
  - `.keychain/` - Directory containing actual key files (`<contact>_enc.key`, `<contact>_dec.key`)

## How to use (encryption / decryption)

There are two ways to use OTP: directly with key files, or with the keychain system for managing multiple contacts.

### Using Key Files Directly

* Create a key file: `printf '%s' 'mysupersecretkey' > key.txt`
* Encrypt using key: `printf '%s' 'topsecretmsg' | otp key.txt > cipher.txt`
* Decrypt using key: `cat cipher.txt | otp key.txt > plain.txt`

#### Next key

Everytime you run the command it will create a new file with the same name as the key file ending with ".next".

### Using the Keychain System

The keychain system provides a convenient way to manage multiple contacts and their encryption/decryption keys. Contact metadata is stored in `keychain.txt`, while actual key files are stored in the `.keychain/` directory. Keys are automatically consumed via offset tracking as you encrypt/decrypt messages, supporting extremely large keys (up to 1TB) through streaming.

#### Setup Keychain

1. **Generate a key pair** (on a secure machine):
   ```bash
   cat /dev/urandom | otp --new-key-pair 1 alice bob
   ```

2. **Distribute keys securely** (via encrypted USB, in-person, etc.):
   - Alice receives: `encryption_alice.txt` and `decryption_alice.txt`
   - Bob receives: `encryption_bob.txt` and `decryption_bob.txt`

3. **Add contacts to keychain**:
   
   On Alice's machine:
   ```bash
   otp --add-contact bob encryption_alice.txt decryption_alice.txt
   ```
   
   On Bob's machine:
   ```bash
   otp --add-contact alice encryption_bob.txt decryption_bob.txt
   ```

#### Encrypt and Decrypt with Keychain

**Alice sends encrypted message to Bob:**
```bash
echo "Hello Bob!" | otp -c bob --encrypt > message.bin
```

**Bob decrypts Alice's message:**
```bash
cat message.bin | otp -c alice --decrypt
# Output: Hello Bob!
```

**Bob sends encrypted reply to Alice:**
```bash
echo "Hi Alice!" | otp -c alice --encrypt > reply.bin
```

**Alice decrypts Bob's reply:**
```bash
cat reply.bin | otp -c bob --decrypt
# Output: Hi Alice!
```

#### Example Workflow

Complete example of secure communication:

```bash
# 1. Generate 1MB key pair
cat /dev/urandom | otp --new-key-pair 1 alice bob

# 2. Alice adds Bob to her keychain
otp --add-contact bob encryption_alice.txt decryption_alice.txt

# 3. Bob adds Alice to his keychain (on his machine)
otp --add-contact alice encryption_bob.txt decryption_bob.txt

# 4. Alice encrypts and sends
echo "Secret message" | otp -c bob --encrypt > msg1.bin
# Transfer msg1.bin to Bob via any channel (it's encrypted)

# 5. Bob decrypts (on his machine)
cat msg1.bin | otp -c alice --decrypt
# Output: Secret message

# 6. Check contact status
otp --show-contact bob
# Shows: key sizes, offsets, sequence number, timestamps, etc.
```

#### Important Notes

- **Key consumption:** Both key file and keychain methods track key consumption via offsets
- **Keychain location:** `keychain.txt` file and `.keychain/` directory are in the current directory
- **File permissions:** Set appropriate permissions:
  - `chmod 600 keychain.txt`
  - `chmod 700 .keychain/`
  - `chmod 600 .keychain/*`
- **Backup:** Back up both `keychain.txt` and `.keychain/` directory securely if needed
- **Key exhaustion:** Monitor key sizes with `--show-contact` to know when to generate new keys
- **Large keys:** Supports keys up to 1TB through streaming architecture - no RAM limitations
