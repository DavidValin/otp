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
- **Metadata tracking:** Sequence numbers, offsets, and timestamps tracked for each contact in its own `.keychain/<contact>.meta` file
- **Perfect forward secrecy:** Key consumption tracked via offsets; past messages can't be decrypted if offset information is lost
- **Binary safe:** Handles binary cipher text correctly
- **Security:** Keys are masked (displayed as *******) when viewing contact info
- **File structure** (all inside `.keychain/`):
  - `<contact>.meta` - one contact's metadata (paths, offsets, sequences) - see "Per-contact metadata files" below
  - `<contact>_enc.key` / `<contact>_dec.key` - that contact's actual key material
  - `<contact>.lock` - that contact's mutual-exclusion lock file (see "Per-contact locking" below)

## How to use (encryption / decryption)

There are two ways to use OTP: directly with key files, or with the keychain system for managing multiple contacts.

### Using Key Files Directly

* Create a key file: `printf '%s' 'mysupersecretkey' > key.txt`
* Encrypt using key: `printf '%s' 'topsecretmsg' | otp key.txt > cipher.txt`
* Decrypt using key: `cat cipher.txt | otp key.txt > plain.txt`

#### Next key

Everytime you run the command it will create a new file with the same name as the key file ending with ".next".

### Using the Keychain System

The keychain system provides a convenient way to manage multiple contacts and their encryption/decryption keys. Each contact's metadata and key files all live under the `.keychain/` directory. Keys are automatically consumed via offset tracking as you encrypt/decrypt messages, supporting extremely large keys (up to 1TB) through streaming.

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
- **Keychain location:** the `.keychain/` directory is in the current directory; everything (keys, metadata, locks) lives inside it
- **File permissions:** Set appropriate permissions:
  - `chmod 700 .keychain/`
  - `chmod 600 .keychain/*`
- **Backup:** Back up the `.keychain/` directory securely if needed
- **Upgrading from an older version:** if a legacy combined `keychain.txt` from a previous version is found, it's transparently migrated to per-contact files on first use and preserved as `keychain.txt.migrated` - see "Per-contact metadata files" below
- **Key exhaustion:** Monitor key sizes with `--show-contact` to know when to generate new keys
- **Large keys:** Supports keys up to 1TB through streaming architecture - no RAM limitations

## Crash-safe key consumption

A one-time pad is only unbreakable if every key byte is used **exactly once** - ever. That guarantee has to hold even if `otp` is killed, the machine loses power, or the disk fills up in the middle of an operation. This is what the keychain encrypt/decrypt path (`src/commit.c`) is designed around, and it's worth understanding if you're relying on this tool for real secrecy.

### Why a naive implementation isn't enough

The obvious approach - encrypt, write the ciphertext to `stdout`, then update the key file and the contact's metadata - has a gap: if the process dies after the ciphertext has left the machine but before the key state is updated, the key range it used still looks "available." The next run reuses it. XORing the two resulting ciphertexts together cancels the key and recovers the XOR of both plaintexts - a catastrophic break of the pad, triggered by nothing more than an unlucky `Ctrl-C` or `kill -9`.

### The fix: commit before delivery, verify everything, never guess on recovery

Every encrypt/decrypt operation goes through three stages, always in this order:

1. **Stage.** The finished ciphertext (or plaintext) is written to a working file, `fsync`'d, and read back to confirm every byte on disk matches what was intended - a successful `fwrite()` only proves libc accepted the bytes, not that they're durably and correctly on disk. It's then published under a permanent name tagged with the exact key range it corresponds to: `<contact>_enc_pending_seq<N>_off<O>_len<L>.bin` inside `.keychain/`. At this point nothing has been declared "spent" - this is just durable evidence.
2. **Commit.** The key file is truncated to remove the consumed prefix (written to a temp file, verified by read-back, then published via an atomic `rename()`), and *only then* is the contact's own `.keychain/<contact>.meta` file rewritten the same way - built in memory, verified, atomically renamed into place. **This order is not arbitrary.** If the metadata file were committed first, a crash between the two would leave it believing a key range is spent while the key file still physically contains those exact, unread, reusable bytes - reopening the reuse hole. Committing the key file first means a crash between the two instead leaves the key file already correctly reduced and the metadata merely lagging behind - a state that's always safely recoverable, never a reuse risk.
3. **Deliver.** Only once both commits are durable does the staged file get streamed to the real output. Because the ciphertext already exists, verified, on local disk, delivery is now a plain, freely-retryable step - a failure here can't lose or duplicate anything, it just needs to happen again.

### Recovering from a crash

Every encrypt/decrypt call first checks for a leftover pending artifact from an interrupted previous run, before doing anything else. Whichever of the three stages a crash landed in leaves a distinct, unambiguous fingerprint, found by comparing the *physical* size of the key file on disk against what the contact's `.meta` file currently declares and against the range recorded in the pending artifact's own filename:

| Situation on disk | What it means | Recovery action |
|---|---|---|
| Key file size unchanged, `.meta` offset unchanged | Crash before either commit - nothing was ever spent or delivered | Discard the pending file. No key material lost. |
| Key file already shrunk by the pending file's length, `.meta` still stale | Crash between the two commits | Finish the `.meta` update using the range recorded in the pending file's own name - not a guess, the exact numbers it was tagged with - then redeliver. |
| Key file and `.meta` both already reflect the range | Fully committed, only delivery/cleanup was missed | Redeliver the pending file as-is. |

Recovery is automatic - the next `otp -c <contact> --encrypt`/`--decrypt` call handles it without any extra flag - but it's never silent. It prints exactly what happened to `stderr`, e.g.:

```
Recovered incomplete delivery for contact 'bob' (message #5, key range 40960-41060):
redelivering the previously computed ciphertext now instead of processing new input.
Run the command again to encrypt new input.
```

When recovery redelivers a pending message, that invocation does **only** that - it never also processes new input from the same run, so there's no ambiguity about what was actually sent. Run the command again afterward for anything new.

### Why decrypt needs this even more than encrypt

For encryption, the staged artifact is ciphertext - not secret, safe to leave on disk, safe to redeliver any number of times. For decryption, the staged artifact is plaintext, so committing key consumption before it's safely staged would be worse than merely risky: if a crash destroyed the only copy of that plaintext after its key bytes were already gone, the message would be **permanently unrecoverable** - unlike a lost encryption, there's no "just re-encrypt it" option once the corresponding key material no longer exists on either side. Staging the plaintext durably first, under the same `0600` permissions as the key material itself, is what turns that into "redeliver it on the next run" instead of "gone forever."

### Per-contact locking

Crash-safety alone isn't enough if two processes run concurrently against the *same* contact - each would independently read the same starting key offset and each produce individually correct-looking, individually verified output. Staging and read-back verification has no way to detect that, because nothing about either process's own work is wrong in isolation; the problem only exists between them. That requires actual mutual exclusion, not more verification.

Every `encrypt`/`decrypt`/`remove-contact` call for a given contact takes an exclusive lock on `<contact>.lock`, created in the same `.keychain/` directory as that contact's key files and pending artifacts, before touching anything. It's a plain `flock()`, which the kernel releases automatically the moment the holding process's file descriptor closes - including on a crash or `kill -9` - so there is no separate stale-lock state to detect or clean up; it composes directly with the crash-recovery mechanism above rather than needing its own.

A process that has to wait for the lock also **reloads the contact's metadata from disk immediately after acquiring it**, rather than trusting whatever it read when it started. Without this, a process that waited out someone else's operation would still be holding a snapshot from before that operation committed, and would go on to compute key ranges against data that's no longer current - a subtler version of the same problem locking is meant to solve. Two concurrent encryptions for the same contact are therefore fully serialized: whichever acquires the lock first consumes the next key range, and the second sees that consumption reflected before it reads anything.

### Per-contact metadata files

Locking makes two processes on the *same* contact safe, but it doesn't by itself protect two processes on two *different* contacts. Earlier, every contact's metadata lived in one shared `keychain.txt`, rewritten in full on every save - so encrypting for contact A while contact B was concurrently modified elsewhere could still race on that one file: whichever save finished last would win, silently overwriting the other's update with a stale copy of *its own* contact's data. That could never cause key reuse (the physical key file is always the smaller, more-truncated, and therefore authoritative source of truth, so an overstated metadata entry is always caught rather than acted on), but it failed **persistently** - since nothing corrected it automatically, every subsequent attempt for the overwritten contact hit the same mismatch until the metadata was fixed by hand.

The actual fix is to remove the shared file entirely: each contact's metadata now lives in its own `.keychain/<contact>.meta`, written and committed exactly like the key file - `commit_write_verified` then `commit_publish`. Two different contacts write to two entirely different files, so there is no longer any shared mutable state between them to race on at all; this isn't locking working around a shared resource, it's the shared resource not existing anymore.

**Upgrading:** if `otp` finds an old combined `keychain.txt` on load, it migrates every contact out of it into its own `.meta` file, then renames the original to `keychain.txt.migrated` as a preserved backup - nothing is deleted. Migration is idempotent and crash-safe the same way everything else here is: the legacy file is only renamed away as the very last step, once every contact has been written out and verified, so an interrupted migration just re-runs in full on the next load rather than losing whatever hadn't been converted yet.

### Known limitations

- **Contact names are trusted as filesystem-safe:** contact names are used directly in file paths (`<name>.meta`, `<name>_enc.key`, `<name>.lock`, etc.), consistent with how key file paths have always been built. There's no validation against path separators or other filesystem-special characters in a contact name.
