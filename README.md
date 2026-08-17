## One Time Pad "otp" command

This program takes stdin, xor's it with a key file and outputs to stdout.
When it finishes it writes a new file containing the part of the key file that was not used, named after the key file with a timestamp and a `.next` suffix - e.g. `key.txt` produces `key.txt.2026-08-16_19-48-21.next`.

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

Use the `-nk` or `--new-key-pair` flag to generate a new key pair from a source of randomness. Each party receives 2 keys, an encryption key (used for sending messages) and a decryption key (used to receive messages). Each party's pair is written into its own directory, `<name>_keys/`, ready to hand over as one unit, and each file is named for the correspondent it is used with:

```
alice_keys/
   encryption_for_bob.key     <-- the key Alice uses to encrypt messages sent to Bob
   decryption_from_bob.key    <-- the key Alice uses to decrypt messages received from Bob

bob_keys/
   encryption_for_alice.key   <-- the key Bob uses to encrypt messages sent to Alice
   decryption_from_alice.key  <-- the key Bob uses to decrypt messages received from Alice
```

Example (generates 2 key pairs of 1MB length, one pair for each party)
```
cat /dev/urandom | otp --new-key-pair 1 alice bob
```

The key material is read from **stdin**, so the randomness source must be piped in. Run without a pipe (stdin on a terminal) the command refuses immediately - before creating any directory or file - rather than sit waiting for megabytes of typed input.

### The roles are inverted between the two parties

This is the single most important thing to understand about generation, and getting it backwards is the most common way to end up unable to decrypt anything.

**Only two random keys are actually generated.** The command reads two independent chunks from stdin - call them **Key 1** and **Key 2** - and writes each of them out *twice*, under **inverted role names**. What one party calls its *encryption* key, the other calls its *decryption* key:

```
   two random keys           written out as four files, with the roles crossed
   ───────────────           ──────────────────────────────────────────────────

                        ┌──►  alice_keys/encryption_for_bob.key     Alice ENCRYPTS with Key 1
      Key 1 ────────────┤
                        └──►  bob_keys/decryption_from_alice.key    Bob DECRYPTS with Key 1

                        ┌──►  bob_keys/encryption_for_alice.key     Bob ENCRYPTS with Key 2
      Key 2 ────────────┤
                        └──►  alice_keys/decryption_from_bob.key    Alice DECRYPTS with Key 2
```

So `alice_keys/encryption_for_bob.key` and `bob_keys/decryption_from_alice.key` are **byte-identical** - they are the same Key 1 under two different names. Likewise `bob_keys/encryption_for_alice.key` and `alice_keys/decryption_from_bob.key` are both Key 2. That inversion is the entire mechanism: Alice encrypts with Key 1, and Bob can read it because his decryption key *is* Key 1.

The two directories are named after their **owner**; the files inside are named after the **peer** they are used with. Each party takes the whole directory bearing their own name:

| Party | Takes | Which is | Used for |
|---|---|---|---|
| Alice | `alice_keys/encryption_for_bob.key` | Key 1 | encrypting messages she sends to Bob |
| Alice | `alice_keys/decryption_from_bob.key` | Key 2 | decrypting messages she receives from Bob |
| Bob | `bob_keys/encryption_for_alice.key` | Key 2 | encrypting messages he sends to Alice |
| Bob | `bob_keys/decryption_from_alice.key` | Key 1 | decrypting messages he receives from Alice |

Give Alice the `bob_keys/` directory by mistake and both parties will encrypt with the key the other is also encrypting with - every message will decrypt to garbage, and worse, the same key range will be consumed twice for two different messages, breaking the pad. Verify with `cmp` before distributing:

```bash
cmp alice_keys/encryption_for_bob.key bob_keys/decryption_from_alice.key   # must be identical
cmp bob_keys/encryption_for_alice.key alice_keys/decryption_from_bob.key   # must be identical
cmp alice_keys/encryption_for_bob.key bob_keys/encryption_for_alice.key    # must DIFFER
```

See [Two keys per contact](#two-keys-per-contact-mirrored-between-the-two-parties) for why the roles are split this way.

`--add-contact` refuses two key files that overlap, since one pad serving both directions means the range that encrypts an outgoing message also decrypts an incoming one. The comparison is by content, not by name or size, so all these forms are rejected: the same file twice, a copy under a different name, a pad paired with part of itself (a `.next` file or a partially consumed key from `.keychain/` is the *tail* of the pad it came from), and even a slice trimmed at both ends or two windows cut from the same pad - the check searches for each file's opening 64 bytes at *every* offset of the other with a rolling hash, so overlap is found wherever it hides, not only when the files line up at an end. Keys smaller than 64 bytes keep the aligned prefix/suffix comparison only, since a handful of bytes genuinely can coincide in two independent pads. The cost is one sequential read of each file, paid once per add.

The same search runs **across contacts**: a candidate key that overlaps a key already installed for any other contact is refused in the same-direction case (one pad consumed twice from its own start is two messages sharing bytes), and warned about in the mirrored case - new encryption key equals an existing decryption key or vice versa - which is how one machine legitimately operates both endpoints of its own pads for loopback testing in a single directory.

Removed contacts leave nothing to compare against, so `.keychain/spent_heads` keeps a durable fingerprint (two 64-bit digests, never key bytes) of each key's opening 64 bytes, recorded the first time they are consumed. A later `--add-contact` whose file still contains a recorded spent head - which the ORIGINAL distribution copy always does - is refused whatever the contact is now called, while the partially consumed remainder no longer contains it and stays acceptable. One trade-off is made knowingly: a digest of spent pad bytes lets someone who can read `.keychain/` *and* holds a captured ciphertext confirm a complete guess of that message's first 64 plaintext bytes. It recovers nothing on its own, and that reader already holds every live key in the directory; the alternative is the silent two-time pad the registry exists to prevent.

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
- **File structure:** everything lives inside `.keychain/`, one set of files per contact - see below

### The `.keychain/` directory

Everything `otp` stores lives in `.keychain/` in the current directory. There is no shared state between contacts: every file belongs to exactly one contact, and its name begins with that contact's name. This is what lets two contacts be operated on concurrently without any coordination between them.

```
.keychain/                        0700
├── alice.meta                    0600  metadata: key paths, offsets, sequences, timestamps
├── alice_enc.key                 0600  key material for encrypting messages to alice
├── alice_dec.key                 0600  key material for decrypting messages from alice
├── alice.lock                    0600  0-byte mutual-exclusion lock
├── bob.meta                      0600  a second contact - entirely separate files
├── bob_enc.key                   0600
├── bob_dec.key                   0600
└── bob.lock                      0600
```

`--add-contact` creates the `.meta` and the two `.key` files; the `.lock` file appears the first time that contact is used for an encrypt, decrypt or remove.

During an operation, and after an interrupted one, you may also see:

```
.keychain/
├── alice_enc_pending_seq7_off4096_len120.bin      published, verified output awaiting delivery
├── alice_enc_pending.31337.tmp                    output still being staged (pid-tagged)
├── alice_enc.key.tmp                              key file being rewritten minus the consumed prefix
└── alice.meta.tmp                                 metadata being rewritten
```

| File | Lifetime | Purpose |
|---|---|---|
| `<contact>.meta` | permanent | That contact's metadata. The only format this version reads or writes; written via verified-write-then-atomic-rename, so it is never observed half-updated. |
| `<contact>_enc.key`<br>`<contact>_dec.key` | permanent | The actual key material. Consumed from the front and physically truncated after each message, so the file's **size is the remaining key length** - this, not the metadata, is the authority. |
| `<contact>.lock` | permanent | Empty file backing the per-contact `flock()`, created on that contact's first encrypt/decrypt/remove. Deliberately never deleted, even when the contact is removed: unlinking it would let a waiter and a newcomer hold locks on different inodes at the same time. |
| `<contact>_<dir>_pending_seq<N>_off<O>_len<L>.bin` | transient | A finished, fsynced, read-back-verified message, tagged with the exact key range it used. Published *before* any key is declared spent, and deleted once delivered. If one survives a crash, its filename is what recovery reconciles against - see the recovery truth table below. |
| `<contact>_<dir>_pending.<pid>.tmp` | transient | Output still being staged. Never verified or published, so it carries no recoverable meaning; swept away by the next operation on that contact and direction. On the decrypt side it holds plaintext. |
| `<contact>_enc.key.tmp`<br>`<contact>_dec.key.tmp` | transient | The post-truncation key file, staged and verified before being renamed over the real one. |
| `<contact>.meta.tmp` | transient | The metadata file, staged and verified the same way. |

`<dir>` is `enc` or `dec`. Every transient file is either published by an atomic `rename()` or cleaned up; none of them is ever the only copy of anything that matters. Seeing one after a crash is normal - the next `otp -c <contact>` call reconciles it.

Everything here is created `0600` (the directory `0700`), key material included, from the moment it is written. Back up the whole directory together: a `.meta` file restored without its matching key file, or vice versa, is a mismatch `otp` will refuse to act on rather than risk reusing key material.

### Stages of one encrypt/decrypt operation

What follows is the actual order of operations in `encrypt_with_contact()` / `decrypt_with_contact()` (`src/keychain.c`), down to the individual `src/commit.c` primitives. The two directions are the same code path with `enc`/`dec` substituted; the only differences are noted at the end. The design rationale for the ordering is in "Crash-safe key consumption" below - this is the mechanical version.

**Phase 1 - Acquire (`encrypt_with_contact`)**

1. `find_contact()` - fail early if the name is unknown.
2. `get_keychain_dir()` - resolve `.keychain/`, creating it `0700` if absent.
3. `contact_lock_acquire()` - `open(<contact>.lock, O_CREAT|O_RDWR, 0600)` then `flock(fd, LOCK_EX)`. **Blocks here** until any other process working on this contact finishes.
4. `load_keychain()` - re-read every `<contact>.meta` from disk, *after* the lock is held. Whatever was read at startup may have been superseded by the process we just waited for.
5. `find_contact()` again - the reload invalidated the earlier pointer.

Everything below runs under the lock, in `encrypt_with_contact_locked()`.

**Phase 2 - Reconcile**

6. `commit_reconcile()` - one `opendir(.keychain)` pass that unlinks any `<contact>_<dir>_pending.<pid>.tmp` (abandoned staging: unverified, no recoverable meaning) and locates a published `<contact>_<dir>_pending_seq<N>_off<O>_len<L>.bin`. Only if such an artifact exists does it then `otp_file_size()` the key file and weigh that, the `.meta` values, and the artifact's own filename tag against the three-window truth table. With no artifact - the normal case - it returns immediately.
7. On `FINISH`: apply the corrected offset/size/sequence and `save_contact_meta()`. On `FINISH` or `DELIVER`: `deliver_pending_file()`, `commit_discard_path()`, **return `KEYCHAIN_REDELIVERED` (exit 3)** - this run's input is deliberately not read.
8. `resync_key_size()` - `otp_file_size()` the key file against the `.meta` size. Smaller means the metadata is behind: adopt the file's size, report it, `save_contact_meta()`. Larger means key material was rolled back - **abort**, its leading bytes are already spent.

**Phase 3 - Produce (nothing is committed yet)**

9. `fopen(<contact>_<dir>.key, "rb")` - always from byte 0. The file *is* the unconsumed key; there is no seek-to-offset.
10. `malloc` two 4MB buffers, then `commit_stage_open()` - `unlink` + `open(<contact>_<dir>_pending.<pid>.tmp, O_CREAT|O_EXCL, 0600)`, CRC32 state initialised.
11. Loop until `fread(input)` returns 0:
    - **bounds check** `total + input_bytes > available_key` → abort before any XOR. This is what stops a multi-chunk message from emitting chunks it cannot finish;
    - `fread` the same number of key bytes; a short read aborts;
    - XOR in place;
    - `commit_stage_write()` - append to the staging file and fold into the CRC32. **This is the only sink**; nothing reaches `output` in this loop;
12. `fclose` the key file, free the buffers, reject an empty message.
13. `commit_stage_close_verified()` - `fflush` → `fsync` → `fclose` → **reopen and re-read the file**, recomputing the CRC32 and comparing length and checksum. A successful `fwrite` only proves libc accepted the bytes; this proves they are on disk.

**Phase 4 - Commit (ordering is load-bearing)**

14. `commit_pending_path()` - compose the name tagging the exact range: sequence `EncryptedSequence + 1`, offset `EncryptionKeyOffset`, length `total_bytes`.
15. `commit_publish()` - `otp_rename_replace()` the staging file to that name, then `fsync` the containing directory so the rename survives power loss and not just a kill (POSIX; a no-op on Windows, which has no directory handle to sync). The message now exists durably, tagged, but **no key is declared spent**. `[crash point: after_pending_publish]`
16. `truncate_key_file()` - `otp_fseek()` past the consumed prefix, stream the remainder in 4MB chunks through a fresh `CommitStage` into `<contact>_<dir>.key.tmp`, `commit_stage_close_verified()` it, then `commit_publish()` it over the real key file. The consumed bytes are now physically gone. `[crash point: after_key_publish]`
17. Update the in-memory contact: sequence, offset `+= total_bytes`, size `= remaining`, timestamp.
18. `save_contact_meta()` - build the whole file in memory, `commit_write_verified()` it to `<contact>.meta.tmp` (write → `fsync` → reopen → **byte-for-byte `memcmp`**), then `commit_publish()`. `[crash point: after_keychain_save]`

Steps 15, 16 and 18 are the only three durable state changes, and they happen in that order. Reversing 16 and 18 would let a crash leave the metadata calling a range spent while the key file still physically held those exact reusable bytes.

**Phase 5 - Deliver**

19. `deliver_pending_file()` - stream the published artifact to `output` in 64KB reads. By now both commits are durable, so this step is freely retryable and cannot affect key state.
20. `commit_discard_path()` - unlink the artifact.
21. Report bytes used and key remaining on `stderr`; `contact_lock_release()` on the way out.

**Where a crash lands.** Before step 15, nothing exists and nothing was spent. Between 15 and 16, the artifact exists but no key was consumed - discarded. Between 16 and 18, key consumed but metadata stale - finished from the artifact's filename, then redelivered. After 18, everything committed - redelivered. Recovery is step 6 of the next run; the truth table is below.

The same four outcomes cover an I/O failure as well as a crash: a `.meta` write that fails after the key file is already committed leaves exactly the between-16-and-18 state, and recovers identically.

**Decrypt differs in exactly one way:** the artifact holds plaintext rather than ciphertext - which is why staging it before spending key matters more, not less, since a lost plaintext cannot be recomputed once its key bytes are gone - and `LastMessageReceivedAt` is stamped instead of `LastMessageSentAt`.

## One Time Pad algorithm requirements

The one-time pad is the only encryption scheme with a proof of perfect secrecy, but that proof rests entirely on two conditions. Break either one and the guarantee is not weakened, it is gone:

1. **The key must be fully random.** Every key byte must be independent and uniformly distributed. A key from a PRNG is only as strong as that PRNG's seed, which reduces the pad to a stream cipher. Use a hardware entropy source - see [True Random key generator](#true-random-key-generator) above.
2. **A piece of key may be used exactly once - ever.** Not once per direction, not once per machine, not "probably once". If two messages are ever encrypted with the same key range, XORing the two ciphertexts cancels the key entirely and yields the XOR of the two plaintexts, from which both are routinely recoverable.

Requirement 1 is a property of how the key is generated, and is outside this tool's control beyond `--new-key-pair`. Requirement 2 is a property of how the key is *consumed*, and is what everything below exists to enforce.

Requirement 2 also has a transport-side corollary the tool cannot verify by itself: ciphertext carries no key-range tag, so within one direction messages must be decrypted in the exact order they were sent, complete, exactly once. A message lost, reordered, duplicated or truncated in transit would make the next decrypt use the wrong key range - emitting garbage with exit code 0 while destroying the key bytes the real messages needed. Only the correspondents can confirm delivery, out of band, so `otp` makes that an enforced checkpoint: before spending key on any message after a direction's first, it asks on the terminal (never on `stdin`, which carries the message itself) whether the previous message in that direction - identified by its sequence number, date, and key offset - arrived and decoded correctly, and cancels with the keys untouched unless answered yes. Once you have confirmed out of band, pass `-y`/`--assume-delivered` (or set `OTP_ASSUME_DELIVERED=1`) to skip the prompt; scripts must do so explicitly, because with no terminal to ask on the operation fails closed rather than assuming delivery. Crash-recovery redelivery is never gated - it re-emits already-committed output and consumes no new key.

## Accidental mid-crash protection

The one-time pad requires that the key portion used to encrypt a plaintext is never reused. Although this seems straightforward to implement, there are accidents along the way - a `kill -9`, a power cut, a full disk, a broken pipe, two invocations racing - and almost all of them land in the gap between *"the message has been produced"* and *"the key has been recorded as spent"*. Anything that leaves that gap open reopens requirement 2.

Below is each stage of an operation, the accident that can occur at that exact point, and the mechanism that resolves it. Stage numbers refer to the walkthrough above.

### One Time Pad encryption

| Stage | Accident | How it's solved |
|---|---|---|
| 1. Acquire lock (3) | Two processes encrypt for the same contact at once. Each reads the same starting offset and each produces individually valid output - using the same key bytes twice. | Exclusive per-contact `flock()` on `<contact>.lock`. The second process blocks until the first has fully committed. Verification alone cannot catch this: neither process is wrong in isolation. |
| 1. Reload (4) | The process read its metadata at startup, then waited on the lock. It now holds a snapshot from *before* the operation it just waited for, and would compute key ranges that are already spent. | `load_keychain()` is re-run *after* the lock is acquired, so the operation always starts from authoritative on-disk state. |
| 2. Reconcile (6-7) | A previous run died mid-commit. Its key range may or may not already be spent, and guessing wrong either wastes key or reuses it. | The artifact's filename records the exact range it used. Comparing the physical key file size, the `.meta` values and that tag identifies which of three windows the crash landed in - deterministically, never heuristically. |
| 2. Resync (8) | A restored backup or hand-edited `.meta` disagrees with the key file. If it overstates the remaining key, every later operation fails permanently; if the *key file* was rolled back, its leading bytes are already spent and reusing them breaks the pad. | The key file is authoritative (bytes are consumed from the front and it is truncated). Smaller than the metadata claims: adopt the file's size and continue. Larger: refuse outright and tell the user to re-key. |
| 3. Produce (11) | The message turns out to be longer than the remaining key partway through. A streaming implementation that writes as it goes has already emitted the first chunks - key material is now exposed in delivered ciphertext while its range still looks unused. | The length check runs *before* each chunk is XORed, and every chunk is written to a staging file rather than to `output`. Nothing reaches the caller until the whole message is complete and verified. |
| 3. Verify (13) | `fwrite()` succeeded, but the bytes never reached the platter, or reached it corrupted. Key would be spent on a message that cannot actually be delivered. | `commit_stage_close_verified()` fsyncs, then reopens the file and recomputes a CRC32 over what is *actually on disk*, comparing both length and checksum. |
| 4. Publish artifact (15) | Crash immediately after the ciphertext is published. | Nothing was spent and nothing was delivered, so the artifact is stale evidence. Recovery discards it; no key is lost and the next run proceeds normally. |
| 4. Truncate key (16) | Crash between consuming the key and recording it - or during the truncation itself, leaving a half-rewritten key file. | The key file is only ever replaced by an atomic rename of a separately staged, verified copy, so it is never observed half-written. A crash here leaves it correctly shrunk with stale metadata, which recovery completes from the artifact's filename tag. |
| 4. Ordering (16 before 18) | If metadata were committed first, a crash between the two would leave it declaring a range spent while the key file still physically held those exact bytes - unread, and reusable by the next run. | Key file first, always. The reverse crash is then merely a stale record, never a live reuse hole. |
| 4. Save metadata (18) | Crash during the metadata write leaves a truncated `.meta` and an unreadable contact. | Built entirely in memory, written to `.meta.tmp`, fsynced, reopened and compared byte-for-byte, then atomically renamed. The live `.meta` only ever transitions between two complete versions. |
| 5. Deliver (19) | Broken pipe, full disk, or a crash while streaming to `stdout` - after the key has already been consumed. Naively, the message is gone and the key with it. | Both commits are already durable and the verified artifact is still on disk. The next run detects a fully-committed state and redelivers it byte-identically. Delivery is retryable precisely because it happens last. |
| 5. Redelivery | The redelivering run was also given fresh input on `stdin`. Processing both would blur which message was actually sent. | A recovering run redelivers *only*, never also encrypting new input, and exits `3` instead of `0` so a script cannot mistake it for having sent its own message. |

### One Time Pad decryption

Decryption runs the identical protocol, but the stakes at one specific point are different: the staged artifact is **plaintext**, and unlike ciphertext it cannot be recomputed once the corresponding key bytes are gone from both sides.

| Stage | Accident | How it's solved |
|---|---|---|
| 1. Acquire lock (3) | Two processes decrypt for the same contact at once, both consuming the same decryption key range. | The same exclusive per-contact `flock()`; encrypt, decrypt and remove all take it. |
| 2. Reconcile / resync (6-8) | An interrupted decrypt left the decryption key and `.meta` out of step, or a restored backup rolled the decryption key back. | The same truth table and the same authoritative-key-file rule, applied to the `dec` direction independently of `enc`. |
| 3. Produce (11) | Ciphertext arrives longer than the remaining decryption key, discovered partway through. | The same pre-XOR bounds check, and the same "staging file is the only sink" rule. |
| 3. Verify (13) | The recovered plaintext is written but not durably or correctly on disk when the key is about to be destroyed. | Same fsync-and-read-back verification - and here it is the difference between a recoverable message and a permanently lost one. |
| 4. Commit (15-18) | **The defining case:** a crash after the decryption key bytes are consumed but before the plaintext is safe on disk. The ciphertext alone is now undecryptable forever, because the key that produced it no longer exists on either side. | The plaintext is staged, fsynced, verified and published *before* any key is declared spent. The worst a crash can do is require a redelivery, never a loss. |
| Aborted staging | A process killed mid-decrypt leaves a partial staging file that contains real recovered plaintext sitting in `.keychain/`. | Abandoned `<contact>_dec_pending.<pid>.tmp` files are swept by the next operation on that contact and direction, and removing a contact deletes every trace of its staged content. |
| 5. Deliver (19) | Crash or broken pipe while writing plaintext to `stdout`, after the key is gone. | The verified plaintext is still on disk; the next run redelivers it exactly, and exits `3` so the caller knows its own input was not processed. |

### What this does not cover

Everything above protects requirement 2 against **accidents inside one keychain**: no crash, kill, power loss, disk error or concurrent invocation can make the same key range cover two messages. That guarantee rests on one precondition the program cannot enforce - that the keychain directory is never rolled back or duplicated. The authority for "what is still unspent" is the key file's own length, which is self-evidently correct as long as it only ever moves forwards. Nothing outside it records that a byte was spent, so anything that turns the clock back is invisible:

- **Restoring `.keychain/` from a backup is total, silent key reuse.** Snapshot the directory, send a message, restore the snapshot, send another - both messages are encrypted with the same key range, and XORing the two ciphertexts recovers the XOR of the two plaintexts. Exit status 0, no warning. The rolled-back-key refusal does *not* catch this, because the key file and its metadata were rolled back together and therefore agree with each other; that check only detects an *inconsistent* rollback. **Do not snapshot, sync, or restore `.keychain/` while it is in use.** If you must back it up, treat restoring it as re-keying: the contacts in the restored copy have to be given fresh key material before anything is sent.
- **The same key files on two machines** is the same failure by another route - both consume from offset 0 with no way to learn about each other.
- **Re-adding a contact from the original distribution key** restarts at offset 0 over already-spent bytes. On the *same* keychain this is now refused, not just warned about: the spent-heads registry recognizes the original's opening bytes even after the contact and its key files are gone (see [The roles are inverted between the two parties](#the-roles-are-inverted-between-the-two-parties) above). The registry lives inside `.keychain/`, though, so it shares the directory's rollback blind spot, and it cannot see spending that happened on a *different* machine - only supply key material that has never been used anywhere.
- **The pad is not authenticated.** It provides secrecy, not integrity: a flipped ciphertext bit flips the same plaintext bit undetectably. Nothing here changes that.
- **An attacker with write access to `.keychain/`** can do all of the above deliberately.

Key distribution and requirement 1 remain yours.

## Files written to disk

Everything `otp` creates itself is mode `0600` (and the `.keychain/` directory `0700`) from the moment of creation - key material is never briefly world-readable and is never chmod'd after the fact.

| Mode | Files created | Where |
|---|---|---|
| Keychain (`-c`, `-ac`, `-rc`) | `<contact>.meta`, `<contact>_enc.key`, `<contact>_dec.key`, `<contact>.lock`, plus the transient staging and pending files - see [The `.keychain/` directory](#the-keychain-directory) for the full table | `.keychain/` in the current directory |
| Key-pair generation (`-nk`) | `<a>_keys/encryption_for_<b>.key`, `<a>_keys/decryption_from_<b>.key`, `<b>_keys/encryption_for_<a>.key`, `<b>_keys/decryption_from_<a>.key` (the `<name>_keys/` directories are created `0700`) | current directory |
| Direct key file (`otp <keyfile>`) | `<keyfile>.YYYY-MM-DD_HH-MM-SS.next` | alongside the key file |

**The keychain location is not configurable.** It is always `.keychain/` relative to the process's current working directory, so running `otp` from a different directory uses a different keychain. That is what lets you keep two correspondents' keychains side by side in separate directories.

**Redirected output is not covered by any of this.** Ciphertext and plaintext go to `stdout`; when you redirect it, the file is created by your *shell*, with your umask - typically `0644`:

```bash
otp -c bob --encrypt < secret.txt > cipher.bin   # cipher.bin is 0644, created by the shell
```

Ciphertext being world-readable is harmless, but the same applies to plaintext on the decrypt side. If that matters, set `umask 077` first or write into a directory that is already `0700`.

## How to use (encryption / decryption)

There are two ways to use OTP: directly with key files, or with the keychain system for managing multiple contacts.

### Using Key Files Directly

* Create a key file: `printf '%s' 'mysupersecretkey' > key.txt`
* Encrypt using key: `printf '%s' 'topsecretmsg' | otp key.txt > cipher.txt`
* Decrypt using key: `cat cipher.txt | otp key.txt > plain.txt`

#### Next key

Every time you run the command it creates a new file holding the unused remainder of the key. Its name is the key file's name plus the current local time and a `.next` suffix:

```
key.txt   ->   key.txt.2026-08-16_19-48-21.next
```

It is **not** simply `key.txt.next` - the timestamp is always present, so a script cannot assume a fixed name. The file is created `0600` with `O_CREAT|O_EXCL`, so a second run within the same second fails rather than silently overwriting the first run's remainder.

### Using the Keychain System

The keychain system provides a convenient way to manage multiple contacts and their encryption/decryption keys. Each contact's metadata and key files all live under the `.keychain/` directory. Keys are automatically consumed via offset tracking as you encrypt/decrypt messages, supporting extremely large keys (up to 1TB) through streaming.

#### Two keys per contact, mirrored between the two parties

Every contact in your keychain holds a **key pair**, never a single key:

- `<contact>_enc.key` - consumed only when you **send** to that contact
- `<contact>_dec.key` - consumed only when you **receive** from that contact

The pair is **shared with the other party with the two roles inverted** - the inversion applied at generation time (see [The roles are inverted between the two parties](#the-roles-are-inverted-between-the-two-parties)) carries straight through into the keychain. Your encryption key is byte-identical to their decryption key, and their encryption key is byte-identical to yours. Neither key is ever used for both roles by the same party. The two keychains line up like this:

```
        Alice's .keychain/                              Bob's .keychain/

  bob_enc.key  ─── same bytes (Key 1) ────────────►  alice_dec.key
  (Alice sends)             the roles invert         (Bob receives)

  bob_dec.key  ◄──────────── same bytes (Key 2) ───  alice_enc.key
  (Alice receives)          the roles invert         (Bob sends)
```

Read a row across and the inversion is the whole point: the file Alice consumes to **encrypt** is the same file Bob consumes to **decrypt**.

**Why a pair rather than one shared key: parallel, non-blocking messaging in both directions.** With a single shared key, the two parties would be drawing from the same range, so every message would have to be coordinated - turn-taking, acknowledgements, or some agreed split - and any two messages sent at the same time would collide on the same key bytes and break the pad.

Two independent keys remove that problem by construction. The outgoing and incoming directions consume entirely different files, tracked by entirely separate offsets and sequence numbers (`EncryptionKeyOffset`/`EncryptedSequence` versus `DecryptionKeyOffset`/`DecryptedSequence` in `<contact>.meta`). So:

- Alice can send while Bob is sending. Messages may cross in flight; neither consumes key material the other is using.
- Neither machine ever waits for or is even aware of the other's activity. There is **no protocol-level coordination between the two machines at all** - not even a shared counter.
- The independence is between the two *directions*, not within one: ciphertext carries no key-range tag, so each direction's messages must still be decrypted in the exact order they were sent, complete, exactly once. That in-order property is what the delivery-confirmation prompt (see [One Time Pad algorithm requirements](#one-time-pad-algorithm-requirements)) makes each operator vouch for before more key is spent.

The only serialization is local and brief: on one machine, concurrent operations on the *same* contact take that contact's `.lock` (see [Per-contact locking](#per-contact-locking)), so two processes cannot draw from the same key file at once. Operations on *different* contacts share nothing and run fully in parallel.

Because the two directions are independent, they also exhaust independently - a chatty sender can run out of encryption key while its decryption key is still nearly full. `--show-contact` reports both remaining sizes separately.

#### Setup Keychain

1. **Generate a key pair** (on a secure machine):
   ```bash
   cat /dev/urandom | otp --new-key-pair 1 alice bob
   ```

2. **Distribute keys securely** (via encrypted USB, in-person, etc.):
   - Alice receives the `alice_keys/` directory (`encryption_for_bob.key` and `decryption_from_bob.key`)
   - Bob receives the `bob_keys/` directory (`encryption_for_alice.key` and `decryption_from_alice.key`)

3. **Add contacts to keychain**:
   
   On Alice's machine:
   ```bash
   otp --add-contact bob alice_keys/encryption_for_bob.key alice_keys/decryption_from_bob.key
   ```
   
   On Bob's machine:
   ```bash
   otp --add-contact alice bob_keys/encryption_for_alice.key bob_keys/decryption_from_alice.key
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

# 2. Alice adds Bob to her keychain (using her own alice_keys/ pair)
otp --add-contact bob alice_keys/encryption_for_bob.key alice_keys/decryption_from_bob.key

# 3. Bob adds Alice to his keychain (on his machine, using his bob_keys/ pair)
otp --add-contact alice bob_keys/encryption_for_alice.key bob_keys/decryption_from_alice.key

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
- **File permissions:** everything `otp` creates inside `.keychain/` is created `0600` (and the directory `0700`) - key files included, from the moment they are copied in. No manual `chmod` is needed
- **Backup:** Back up the `.keychain/` directory securely if needed
- **Contact names:** a contact's name is used verbatim as a filename, so names may not be `.` or `..`, contain a path separator (`/` or `\`), any of `: * ? " < > | =`, or control characters. Anything else - spaces, dots, non-ASCII - is fine
- **Key exhaustion:** Monitor key sizes with `--show-contact` to know when to generate new keys
- **Large keys:** Supports keys up to 1TB through streaming architecture - no RAM limitations. Every step that touches a key file streams it in fixed-size chunks, including the truncation that follows each message, so peak memory does not scale with key size
- **Exit codes for `-c`:** `0` success, `3` a recovered message from an interrupted earlier run was redelivered and **this run's input was not processed** (re-run to send it), any other non-zero value an error

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
| None of the above | The artifact's recorded range cannot be reconciled with the key file and the metadata | Discard it without redelivering, and say so. Guessing which range was really spent is the one thing recovery must never do; the run then proceeds normally from the state that *is* known. |
| The key file cannot be read at all | Nothing can be concluded either way - and the failure may be transient (a mount hiccup, fd exhaustion) | Keep the artifact and abort the run, and say so. On the decrypt side the artifact is the *only* copy of the recovered plaintext - its key bytes are already gone - so discarding it over an unreadable key file would turn a transient failure into permanent message loss. A later run reconciles it normally once the key file is readable again; the run must abort rather than proceed, since staging new output next to the kept artifact would create the "more than one artifact" state below. |
| More than one artifact for the same contact and direction | Only one can exist under normal operation, since reconciliation runs before anything new is staged | Discard the extras rather than pick one arbitrarily, for the same reason. |

Recovery is automatic - the next `otp -c <contact> --encrypt`/`--decrypt` call handles it without any extra flag - but it's never silent. It prints exactly what happened to `stderr`, e.g.:

```
Recovered incomplete delivery for contact 'bob' (message #5, key range 40960-41060):
redelivering the previously computed ciphertext now instead of processing new input.
Run the command again to encrypt new input.
```

When recovery redelivers a pending message, that invocation does **only** that - it never also processes new input from the same run, so there's no ambiguity about what was actually sent. Run the command again afterward for anything new.

Because that run produced valid output while leaving its input entirely unprocessed, it exits **`3`**, not `0`. A script that treated it as success would believe its message had been encrypted when the bytes it received actually belong to a different one; the distinct code lets it detect and retry without parsing `stderr`.

### Why decrypt needs this even more than encrypt

For encryption, the staged artifact is ciphertext - not secret, safe to leave on disk, safe to redeliver any number of times. For decryption, the staged artifact is plaintext, so committing key consumption before it's safely staged would be worse than merely risky: if a crash destroyed the only copy of that plaintext after its key bytes were already gone, the message would be **permanently unrecoverable** - unlike a lost encryption, there's no "just re-encrypt it" option once the corresponding key material no longer exists on either side. Staging the plaintext durably first, under the same `0600` permissions as the key material itself, is what turns that into "redeliver it on the next run" instead of "gone forever."

### Per-contact locking

Crash-safety alone isn't enough if two processes run concurrently against the *same* contact - each would independently read the same starting key offset and each produce individually correct-looking, individually verified output. Staging and read-back verification has no way to detect that, because nothing about either process's own work is wrong in isolation; the problem only exists between them. That requires actual mutual exclusion, not more verification.

Every `encrypt`/`decrypt`/`remove-contact` call for a given contact takes an exclusive lock on `<contact>.lock`, created in the same `.keychain/` directory as that contact's key files and pending artifacts, before touching anything. It's a plain `flock()`, which the kernel releases automatically the moment the holding process's file descriptor closes - including on a crash or `kill -9` - so there is no separate stale-lock state to detect or clean up; it composes directly with the crash-recovery mechanism above rather than needing its own.

A process that has to wait for the lock also **reloads the contact's metadata from disk immediately after acquiring it**, rather than trusting whatever it read when it started. Without this, a process that waited out someone else's operation would still be holding a snapshot from before that operation committed, and would go on to compute key ranges against data that's no longer current - a subtler version of the same problem locking is meant to solve. Two concurrent encryptions for the same contact are therefore fully serialized: whichever acquires the lock first consumes the next key range, and the second sees that consumption reflected before it reads anything.

### Per-contact metadata files

Locking makes two processes on the *same* contact safe, but it does nothing for two processes on two *different* contacts - they never contend for the same lock. What protects them is that they have nothing in common to contend over.

Each contact's metadata lives in its own `.keychain/<contact>.meta`, written and committed exactly like the key file: `commit_write_verified` then `commit_publish`. Two different contacts write to two entirely different files, so there is no shared mutable state between them at all. This isn't locking working around a shared resource; it's the shared resource not existing.

`load_keychain()` is a **pure reader** - it writes nothing. That is what makes it safe to call both before any lock is held (at startup) and again after a contact's lock is acquired. If loading wrote, two processes starting at the same time could each persist their own stale view of a contact, one overwriting offsets the other had just committed.

A contact exists if and only if it has a `<contact>.meta` file. Nothing else in the keychain directory is consulted to decide that.

### Self-healing metadata

The key file, not the metadata, is the authority on how much key material remains: bytes are consumed from the front and the file is physically truncated, so its size *is* the remaining length. Metadata can still drift from it - a restored backup, a hand-edit - and without it, every later operation failed with `Failed to read remaining key` and kept failing, because nothing ever re-derived the truth from the file.

Each operation now compares the two before spending any key, and resolves the disagreement in the only direction that is safe:

- **Key file smaller than the metadata claims** - the metadata is simply behind. Adopt the file's size, report the correction on `stderr`, persist it, and carry on.
- **Key file larger than the metadata claims** - this cannot happen through any code path here, because key files only ever shrink. It means key material was restored or rolled back to an older copy, and the extra bytes at the front of the file have already been used once. Continuing would reuse them, so this is **refused** with an explanation rather than "healed."

### Known limitations

- **Delivery is not byte-resumable:** if a crash interrupts the final delivery step partway through writing to `stdout`, recovery redelivers the message from the beginning. Key state stays exactly correct, but a consumer that already received part of the stream will see those bytes twice. The recovery notice on `stderr` and the distinct exit code (`3`) make this detectable rather than silent.
- **Deleted staged files are unlinked, not shredded:** pending artifacts and abandoned staging files are removed with `unlink()`. On a journaling or copy-on-write filesystem, or on flash, their contents may remain recoverable from the underlying media afterwards.
